// NetworkApiCatalog.cpp — see NetworkApiCatalog.h.
#include "NetworkApiCatalog.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <initializer_list>

namespace ds {
namespace {

struct CatalogRow {
    const char* dll;
    const char* key;
    const char* canonical;
    NetworkApiFamily family;
    NetworkStage stage;
    bool lifecycle = false;
};

// Deliberately compact and exact.  Add aliases as rows instead of weakening the
// matcher to substring/prefix rules.
constexpr CatalogRow kCatalog[] = {
    // Winsock name resolution.
    { "ws2_32", "getaddrinfo",     "getaddrinfo",     NetworkApiFamily::Winsock, NetworkStage::Resolve },
    { "ws2_32", "getaddrinfoex",   "GetAddrInfoEx",   NetworkApiFamily::Winsock, NetworkStage::Resolve },
    { "ws2_32", "gethostbyaddr",   "gethostbyaddr",   NetworkApiFamily::Winsock, NetworkStage::Resolve },
    { "ws2_32", "gethostbyname",   "gethostbyname",   NetworkApiFamily::Winsock, NetworkStage::Resolve },
    { "ws2_32", "getnameinfo",     "getnameinfo",     NetworkApiFamily::Winsock, NetworkStage::Resolve },
    { "wsock32", "gethostbyaddr",  "gethostbyaddr",   NetworkApiFamily::Winsock, NetworkStage::Resolve },
    { "wsock32", "gethostbyname",  "gethostbyname",   NetworkApiFamily::Winsock, NetworkStage::Resolve },
    { "dnsapi", "dnsquery",        "DnsQuery",        NetworkApiFamily::DnsApi,  NetworkStage::Resolve },

    // Winsock transport/session setup.
    { "ws2_32", "accept",          "accept",          NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "ws2_32", "acceptex",        "AcceptEx",        NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "ws2_32", "connect",         "connect",         NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "ws2_32", "connectex",       "ConnectEx",       NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "ws2_32", "socket",          "socket",          NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "ws2_32", "wsaconnect",      "WSAConnect",      NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "ws2_32", "wsasocket",       "WSASocket",       NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "ws2_32", "wsastartup",      "WSAStartup",      NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "wsock32", "connect",        "connect",         NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "wsock32", "socket",         "socket",          NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "wsock32", "wsastartup",     "WSAStartup",      NetworkApiFamily::Winsock, NetworkStage::Connect },
    { "ws2_32", "wsacleanup",      "WSACleanup",      NetworkApiFamily::Winsock, NetworkStage::Connect, true },
    { "ws2_32", "closesocket",     "closesocket",     NetworkApiFamily::Winsock, NetworkStage::Connect, true },

    // Winsock payload I/O.
    { "ws2_32", "send",            "send",            NetworkApiFamily::Winsock, NetworkStage::Write },
    { "ws2_32", "sendto",          "sendto",          NetworkApiFamily::Winsock, NetworkStage::Write },
    { "ws2_32", "transmitfile",    "TransmitFile",    NetworkApiFamily::Winsock, NetworkStage::Write },
    { "ws2_32", "wsasend",         "WSASend",         NetworkApiFamily::Winsock, NetworkStage::Write },
    { "ws2_32", "wsasendto",       "WSASendTo",       NetworkApiFamily::Winsock, NetworkStage::Write },
    { "wsock32", "send",           "send",            NetworkApiFamily::Winsock, NetworkStage::Write },
    { "wsock32", "sendto",         "sendto",          NetworkApiFamily::Winsock, NetworkStage::Write },
    { "ws2_32", "recv",            "recv",            NetworkApiFamily::Winsock, NetworkStage::Read },
    { "ws2_32", "recvfrom",        "recvfrom",        NetworkApiFamily::Winsock, NetworkStage::Read },
    { "ws2_32", "wsarecv",         "WSARecv",         NetworkApiFamily::Winsock, NetworkStage::Read },
    { "ws2_32", "wsarecvfrom",     "WSARecvFrom",     NetworkApiFamily::Winsock, NetworkStage::Read },
    { "wsock32", "recv",           "recv",            NetworkApiFamily::Winsock, NetworkStage::Read },
    { "wsock32", "recvfrom",       "recvfrom",        NetworkApiFamily::Winsock, NetworkStage::Read },

    // WinHTTP.
    { "winhttp", "winhttpgetproxyforurl", "WinHttpGetProxyForUrl", NetworkApiFamily::WinHttp, NetworkStage::Resolve },
    { "winhttp", "winhttpopen",           "WinHttpOpen",           NetworkApiFamily::WinHttp, NetworkStage::Connect },
    { "winhttp", "winhttpconnect",        "WinHttpConnect",        NetworkApiFamily::WinHttp, NetworkStage::Connect },
    { "winhttp", "winhttpopenrequest",    "WinHttpOpenRequest",    NetworkApiFamily::WinHttp, NetworkStage::Request },
    { "winhttp", "winhttpaddrequestheaders", "WinHttpAddRequestHeaders", NetworkApiFamily::WinHttp, NetworkStage::Request },
    { "winhttp", "winhttpsetcredentials", "WinHttpSetCredentials", NetworkApiFamily::WinHttp, NetworkStage::Request },
    { "winhttp", "winhttpsendrequest",    "WinHttpSendRequest",    NetworkApiFamily::WinHttp, NetworkStage::Write },
    { "winhttp", "winhttpwritedata",      "WinHttpWriteData",      NetworkApiFamily::WinHttp, NetworkStage::Write },
    { "winhttp", "winhttpreceiveresponse", "WinHttpReceiveResponse", NetworkApiFamily::WinHttp, NetworkStage::Read },
    { "winhttp", "winhttpreaddata",       "WinHttpReadData",       NetworkApiFamily::WinHttp, NetworkStage::Read },
    { "winhttp", "winhttpqueryheaders",   "WinHttpQueryHeaders",   NetworkApiFamily::WinHttp, NetworkStage::Read },
    { "winhttp", "winhttpclosehandle",    "WinHttpCloseHandle",    NetworkApiFamily::WinHttp, NetworkStage::Connect, true },

    // WinINet.
    { "wininet", "internetopen",          "InternetOpen",          NetworkApiFamily::WinInet, NetworkStage::Connect },
    { "wininet", "internetconnect",       "InternetConnect",       NetworkApiFamily::WinInet, NetworkStage::Connect },
    { "wininet", "httpopenrequest",       "HttpOpenRequest",       NetworkApiFamily::WinInet, NetworkStage::Request },
    { "wininet", "internetopenurl",       "InternetOpenUrl",       NetworkApiFamily::WinInet, NetworkStage::Request },
    { "wininet", "httpaddrequestheaders", "HttpAddRequestHeaders", NetworkApiFamily::WinInet, NetworkStage::Request },
    { "wininet", "httpsendrequest",       "HttpSendRequest",       NetworkApiFamily::WinInet, NetworkStage::Write },
    { "wininet", "httpsendrequestex",     "HttpSendRequestEx",     NetworkApiFamily::WinInet, NetworkStage::Write },
    { "wininet", "internetwritefile",     "InternetWriteFile",     NetworkApiFamily::WinInet, NetworkStage::Write },
    { "wininet", "httpendrequest",        "HttpEndRequest",        NetworkApiFamily::WinInet, NetworkStage::Write },
    { "wininet", "internetreadfile",      "InternetReadFile",      NetworkApiFamily::WinInet, NetworkStage::Read },
    { "wininet", "internetreadfileex",    "InternetReadFileEx",    NetworkApiFamily::WinInet, NetworkStage::Read },
    { "wininet", "httpqueryinfo",         "HttpQueryInfo",         NetworkApiFamily::WinInet, NetworkStage::Read },
    { "wininet", "internetclosehandle",   "InternetCloseHandle",   NetworkApiFamily::WinInet, NetworkStage::Connect, true },

    // URLMon performs an entire request internally.  Request is the primary
    // static stage; it is not treated as proof that a response was received.
    { "urlmon", "urldownloadtofile",       "URLDownloadToFile",      NetworkApiFamily::UrlMon, NetworkStage::Request },
    { "urlmon", "urldownloadtocachefile",  "URLDownloadToCacheFile", NetworkApiFamily::UrlMon, NetworkStage::Request },
    { "urlmon", "urlopenstream",           "URLOpenStream",          NetworkApiFamily::UrlMon, NetworkStage::Request },
    { "urlmon", "urlopenpullstream",       "URLOpenPullStream",      NetworkApiFamily::UrlMon, NetworkStage::Request },
    { "urlmon", "urlopenblockingstream",   "URLOpenBlockingStream",  NetworkApiFamily::UrlMon, NetworkStage::Request },
};

static char asciiLower(char c) {
    const unsigned char u = static_cast<unsigned char>(c);
    return static_cast<char>(std::tolower(u));
}

static std::string trim(std::string_view value) {
    size_t first = 0, last = value.size();
    while (first < last && std::isspace(static_cast<unsigned char>(value[first]))) ++first;
    while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) --last;
    return std::string(value.substr(first, last - first));
}

static bool allDigits(std::string_view value) {
    if (value.empty()) return false;
    for (char c : value)
        if (c < '0' || c > '9') return false;
    return true;
}

static const CatalogRow* rowByKey(std::string_view key) {
    for (const CatalogRow& row : kCatalog)
        if (key == row.key) return &row;
    return nullptr;
}

static bool oneOf(std::string_view value,
                  std::initializer_list<std::string_view> choices) {
    for (const std::string_view choice : choices)
        if (value == choice) return true;
    return false;
}

static NetworkApiReturnContract makeContract(
    NetworkReturnKind kind,
    NetworkReturnSuccessRule successRule,
    NetworkFailureSentinel failureSentinel,
    std::string_view returnType,
    std::string_view successMeaning,
    std::string_view failureMeaning,
    bool asyncPendingPossible = false,
    NetworkZeroResultMeaning zeroResultMeaning = NetworkZeroResultMeaning::None,
    bool closesResourceOnSuccess = false) {
    NetworkApiReturnContract result;
    result.returnKind = kind;
    result.successRule = successRule;
    result.failureSentinel = failureSentinel;
    result.returnType = returnType;
    result.successMeaning = successMeaning;
    result.failureMeaning = failureMeaning;
    result.asyncPendingPossible = asyncPendingPossible;
    result.pendingRule = asyncPendingPossible
        ? NetworkAsyncPendingRule::LastErrorIoPending
        : NetworkAsyncPendingRule::None;
    result.zeroResultMeaning = zeroResultMeaning;
    result.closesResourceOnSuccess = closesResourceOnSuccess;
    return result;
}

static void addOut(NetworkApiReturnContract& contract,
                   uint8_t oneBasedOrdinal,
                   NetworkOutParameterRole role,
                   NetworkOutParameterValidity validity,
                   bool inOut,
                   std::string_view meaning) {
    if (contract.outParameterCount >= contract.outParameters.size()) return;
    NetworkApiOutParameter& output =
        contract.outParameters[contract.outParameterCount++];
    output.argumentIndex = oneBasedOrdinal > 0
        ? static_cast<uint8_t>(oneBasedOrdinal - 1)
        : 0;
    output.role = role;
    output.validity = validity;
    output.inOut = inOut;
    output.meaning = meaning;
}

static std::optional<NetworkApiReturnContract>
contractFor(const NetworkApiMatch& match) {
    const std::string_view key = match.normalizedName;

    if (key == "getaddrinfo") {
        auto result = makeContract(
            NetworkReturnKind::IntStatus, NetworkReturnSuccessRule::Zero,
            NetworkFailureSentinel::NonZeroStatus, "INT",
            "0: ppResult receives a linked address list",
            "nonzero EAI_* or Winsock status: no completed result list");
        addOut(result, 4, NetworkOutParameterRole::AddressList,
               NetworkOutParameterValidity::OnSuccess, false,
               "addrinfo list; caller releases it with freeaddrinfo");
        return result;
    }
    if (key == "getaddrinfoex") {
        auto result = makeContract(
            NetworkReturnKind::IntStatus, NetworkReturnSuccessRule::Zero,
            NetworkFailureSentinel::NonZeroStatus, "INT",
            "0: ppResult receives the completed address list",
            "nonzero Winsock status; WSA_IO_PENDING means completion is outstanding",
            true);
        result.pendingRule = NetworkAsyncPendingRule::DirectStatusIoPending;
        addOut(result, 6, NetworkOutParameterRole::AddressList,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "ADDRINFOEX list; caller releases it with FreeAddrInfoEx");
        addOut(result, 10, NetworkOutParameterRole::AsyncOperationHandle,
               NetworkOutParameterValidity::OnAsyncPending, false,
               "optional lookup handle used to cancel an outstanding asynchronous query");
        return result;
    }
    if (oneOf(key, {"gethostbyaddr", "gethostbyname"})) {
        return makeContract(
            NetworkReturnKind::Pointer, NetworkReturnSuccessRule::NonNull,
            NetworkFailureSentinel::Null, "hostent*",
            "non-NULL: points to an API-owned host entry",
            "NULL: name lookup failed; WSAGetLastError supplies the reason");
    }
    if (key == "getnameinfo") {
        auto result = makeContract(
            NetworkReturnKind::IntStatus, NetworkReturnSuccessRule::Zero,
            NetworkFailureSentinel::NonZeroStatus, "INT",
            "0: requested host/service text was written",
            "nonzero EAI_* or Winsock status");
        addOut(result, 3, NetworkOutParameterRole::HostText,
               NetworkOutParameterValidity::OnSuccess, false,
               "host buffer receives the numeric or resolved host name");
        addOut(result, 5, NetworkOutParameterRole::ServiceText,
               NetworkOutParameterValidity::OnSuccess, false,
               "service buffer receives the service name or numeric port");
        return result;
    }
    if (key == "dnsquery") {
        auto result = makeContract(
            NetworkReturnKind::IntStatus, NetworkReturnSuccessRule::Zero,
            NetworkFailureSentinel::NonZeroStatus, "DNS_STATUS",
            "ERROR_SUCCESS (0): ppQueryResults receives DNS records",
            "nonzero DNS/Win32 status: query did not complete successfully");
        addOut(result, 6, NetworkOutParameterRole::DnsRecordList,
               NetworkOutParameterValidity::OnSuccess, false,
               "DNS_RECORD list; caller releases it with DnsRecordListFree");
        return result;
    }

    if (key == "accept") {
        auto result = makeContract(
            NetworkReturnKind::SocketHandle,
            NetworkReturnSuccessRule::NotInvalidSocket,
            NetworkFailureSentinel::InvalidSocket, "SOCKET",
            "a valid connected socket accepted from the listen queue",
            "INVALID_SOCKET: accept failed; WSAGetLastError supplies the reason");
        addOut(result, 2, NetworkOutParameterRole::SocketAddress,
               NetworkOutParameterValidity::OnSuccess, false,
               "optional peer socket address");
        addOut(result, 3, NetworkOutParameterRole::SocketAddressLength,
               NetworkOutParameterValidity::OnSuccess, true,
               "input capacity, then actual peer-address length");
        return result;
    }
    if (key == "acceptex") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: accept and optional initial receive completed synchronously",
            "FALSE: failure, or ERROR_IO_PENDING when overlapped completion remains",
            true);
        addOut(result, 3, NetworkOutParameterRole::PayloadBuffer,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "output buffer contains optional initial data and local/remote addresses");
        addOut(result, 7, NetworkOutParameterRole::ByteCount,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "bytes of initial payload received, excluding address blocks");
        return result;
    }
    if (oneOf(key, {"connect", "wsaconnect"})) {
        auto result = makeContract(
            NetworkReturnKind::IntStatus, NetworkReturnSuccessRule::Zero,
            NetworkFailureSentinel::SocketError, "INT",
            "0: connection completed synchronously",
            "SOCKET_ERROR: failure, or nonblocking connection still in progress",
            true);
        result.pendingRule = NetworkAsyncPendingRule::LastErrorNonblockingConnect;
        return result;
    }
    if (key == "connectex") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: connection completed synchronously",
            "FALSE: failure, or ERROR_IO_PENDING when overlapped completion remains",
            true);
        addOut(result, 6, NetworkOutParameterRole::ByteCount,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "bytes sent from the optional initial-data buffer");
        return result;
    }
    if (oneOf(key, {"socket", "wsasocket"})) {
        return makeContract(
            NetworkReturnKind::SocketHandle,
            NetworkReturnSuccessRule::NotInvalidSocket,
            NetworkFailureSentinel::InvalidSocket, "SOCKET",
            "a valid socket handle owned by the caller",
            "INVALID_SOCKET: creation failed; WSAGetLastError supplies the reason");
    }
    if (key == "wsastartup") {
        auto result = makeContract(
            NetworkReturnKind::IntStatus, NetworkReturnSuccessRule::Zero,
            NetworkFailureSentinel::NonZeroStatus, "INT",
            "0: requested Winsock version initialized",
            "nonzero Winsock status returned directly (not via WSAGetLastError)");
        addOut(result, 2, NetworkOutParameterRole::SessionData,
               NetworkOutParameterValidity::OnSuccess, false,
               "WSADATA receives negotiated version and implementation details");
        return result;
    }
    if (oneOf(key, {"wsacleanup", "closesocket"})) {
        return makeContract(
            NetworkReturnKind::IntStatus, NetworkReturnSuccessRule::Zero,
            NetworkFailureSentinel::SocketError, "INT",
            "0: Winsock resource/session release succeeded",
            "SOCKET_ERROR: release failed; WSAGetLastError supplies the reason",
            false, NetworkZeroResultMeaning::None, true);
    }

    if (oneOf(key, {"send", "sendto"})) {
        return makeContract(
            NetworkReturnKind::SignedByteCount,
            NetworkReturnSuccessRule::NonNegative,
            NetworkFailureSentinel::SocketError, "INT",
            "nonnegative: number of payload bytes accepted for sending",
            "SOCKET_ERROR (-1): send failed; WSAGetLastError supplies the reason");
    }
    if (key == "transmitfile") {
        return makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: transmit operation completed synchronously",
            "FALSE: failure, or WSA_IO_PENDING when overlapped completion remains",
            true);
    }
    if (oneOf(key, {"wsasend", "wsasendto"})) {
        auto result = makeContract(
            NetworkReturnKind::IntStatus, NetworkReturnSuccessRule::Zero,
            NetworkFailureSentinel::SocketError, "INT",
            "0: send completed or was accepted synchronously",
            "SOCKET_ERROR: failure, or WSA_IO_PENDING for overlapped completion",
            true);
        addOut(result, 4, NetworkOutParameterRole::ByteCount,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "total bytes sent across the WSABUF array");
        return result;
    }
    if (oneOf(key, {"recv", "recvfrom"})) {
        auto result = makeContract(
            NetworkReturnKind::SignedByteCount,
            NetworkReturnSuccessRule::NonNegative,
            NetworkFailureSentinel::SocketError, "INT",
            "positive: payload bytes received; 0: graceful stream close or an empty message",
            "SOCKET_ERROR (-1): receive failed; WSAGetLastError supplies the reason",
            false, NetworkZeroResultMeaning::EndOfStreamOrEmptyMessage);
        addOut(result, 2, NetworkOutParameterRole::PayloadBuffer,
               NetworkOutParameterValidity::OnSuccess, false,
               "buffer contains exactly the nonnegative byte count returned");
        if (key == "recvfrom") {
            addOut(result, 5, NetworkOutParameterRole::SocketAddress,
                   NetworkOutParameterValidity::OnSuccess, false,
                   "source socket address for the received datagram");
            addOut(result, 6, NetworkOutParameterRole::SocketAddressLength,
                   NetworkOutParameterValidity::OnSuccess, true,
                   "input capacity, then actual source-address length");
        }
        return result;
    }
    if (oneOf(key, {"wsarecv", "wsarecvfrom"})) {
        auto result = makeContract(
            NetworkReturnKind::IntStatus, NetworkReturnSuccessRule::Zero,
            NetworkFailureSentinel::SocketError, "INT",
            "0: receive completed or was accepted synchronously",
            "SOCKET_ERROR: failure, or WSA_IO_PENDING for overlapped completion",
            true);
        addOut(result, 2, NetworkOutParameterRole::PayloadBuffer,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "WSABUF array receives payload bytes");
        addOut(result, 4, NetworkOutParameterRole::ByteCount,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "total payload bytes received across the WSABUF array");
        addOut(result, 5, NetworkOutParameterRole::Flags,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, true,
               "input receive flags, then output message flags");
        if (key == "wsarecvfrom") {
            addOut(result, 6, NetworkOutParameterRole::SocketAddress,
                   NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
                   "source socket address");
            addOut(result, 7, NetworkOutParameterRole::SocketAddressLength,
                   NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, true,
                   "input capacity, then actual source-address length");
        }
        return result;
    }

    if (key == "winhttpgetproxyforurl") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: proxy configuration was determined",
            "FALSE: proxy lookup failed; GetLastError supplies the reason");
        addOut(result, 4, NetworkOutParameterRole::ProxyInfo,
               NetworkOutParameterValidity::OnSuccess, false,
               "WINHTTP_PROXY_INFO receives access type, proxy and bypass strings");
        return result;
    }
    if (oneOf(key, {"winhttpopen", "winhttpconnect", "winhttpopenrequest"})) {
        return makeContract(
            NetworkReturnKind::InternetHandle, NetworkReturnSuccessRule::NonNull,
            NetworkFailureSentinel::Null, "HINTERNET",
            "non-NULL: caller owns the created WinHTTP handle",
            "NULL: handle creation failed; GetLastError supplies the reason");
    }
    if (oneOf(key, {"winhttpaddrequestheaders", "winhttpsetcredentials"})) {
        return makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: request metadata was applied to the handle",
            "FALSE: operation failed; GetLastError supplies the reason");
    }
    if (key == "winhttpsendrequest") {
        return makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: request send completed synchronously",
            "FALSE: failure, or ERROR_IO_PENDING for an asynchronous handle",
            true);
    }
    if (key == "winhttpwritedata") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: write completed synchronously",
            "FALSE: failure, or ERROR_IO_PENDING for an asynchronous handle",
            true);
        addOut(result, 4, NetworkOutParameterRole::ByteCount,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "payload bytes written; asynchronous value belongs to completion");
        return result;
    }
    if (key == "winhttpreceiveresponse") {
        return makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: response headers became available synchronously",
            "FALSE: failure, or ERROR_IO_PENDING for an asynchronous handle",
            true);
    }
    if (key == "winhttpreaddata") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: read completed; a zero byte count means end of response body",
            "FALSE: failure, or ERROR_IO_PENDING for an asynchronous handle",
            true, NetworkZeroResultMeaning::EndOfBody);
        addOut(result, 2, NetworkOutParameterRole::PayloadBuffer,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "buffer receives the bytes reported by argument 4");
        addOut(result, 4, NetworkOutParameterRole::ByteCount,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "payload bytes read; zero marks end of response body");
        return result;
    }
    if (key == "winhttpqueryheaders") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: requested response-header value was copied",
            "FALSE: query failed; ERROR_INSUFFICIENT_BUFFER still reports required size");
        addOut(result, 4, NetworkOutParameterRole::HeaderBuffer,
               NetworkOutParameterValidity::OnSuccess, false,
               "buffer receives the requested raw or parsed header value");
        addOut(result, 5, NetworkOutParameterRole::BufferSize,
               NetworkOutParameterValidity::OnSuccessOrRequiredSize, true,
               "input buffer bytes, then bytes written or required");
        addOut(result, 6, NetworkOutParameterRole::QueryIndex,
               NetworkOutParameterValidity::OnSuccess, true,
               "enumeration index advances when matching headers are returned");
        return result;
    }
    if (key == "winhttpclosehandle") {
        return makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: handle was closed and pending operations were cancelled",
            "FALSE: close failed; GetLastError supplies the reason",
            false, NetworkZeroResultMeaning::None, true);
    }

    if (oneOf(key, {"internetopen", "internetconnect", "httpopenrequest",
                    "internetopenurl"})) {
        return makeContract(
            NetworkReturnKind::InternetHandle, NetworkReturnSuccessRule::NonNull,
            NetworkFailureSentinel::Null, "HINTERNET",
            "non-NULL: caller owns the created WinINet handle",
            "NULL: handle creation/open failed; GetLastError supplies the reason");
    }
    if (key == "httpaddrequestheaders") {
        return makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: request headers were added or replaced",
            "FALSE: header update failed; GetLastError supplies the reason");
    }
    if (oneOf(key, {"httpsendrequest", "httpsendrequestex", "httpendrequest"})) {
        return makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: request operation completed synchronously",
            "FALSE: failure, or ERROR_IO_PENDING for asynchronous completion",
            true);
    }
    if (key == "internetwritefile") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: write completed synchronously",
            "FALSE: failure, or ERROR_IO_PENDING for asynchronous completion",
            true);
        addOut(result, 4, NetworkOutParameterRole::ByteCount,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "payload bytes written; asynchronous value belongs to completion");
        return result;
    }
    if (key == "internetreadfile") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: read completed; a zero byte count means end of file/response",
            "FALSE: failure, or ERROR_IO_PENDING for asynchronous completion",
            true, NetworkZeroResultMeaning::EndOfBody);
        addOut(result, 2, NetworkOutParameterRole::PayloadBuffer,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "buffer receives the bytes reported by argument 4");
        addOut(result, 4, NetworkOutParameterRole::ByteCount,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, false,
               "payload bytes read; zero marks end of file/response");
        return result;
    }
    if (key == "internetreadfileex") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: INTERNET_BUFFERS receive fields were updated synchronously",
            "FALSE: failure, or ERROR_IO_PENDING for asynchronous completion",
            true, NetworkZeroResultMeaning::EndOfBody);
        addOut(result, 2, NetworkOutParameterRole::PayloadBuffer,
               NetworkOutParameterValidity::OnSuccessOrAsyncCompletion, true,
               "INTERNET_BUFFERS receives payload; dwBufferLength becomes bytes read");
        return result;
    }
    if (key == "httpqueryinfo") {
        auto result = makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: requested response-header value was copied",
            "FALSE: query failed; ERROR_INSUFFICIENT_BUFFER still reports required size");
        addOut(result, 3, NetworkOutParameterRole::HeaderBuffer,
               NetworkOutParameterValidity::OnSuccess, false,
               "buffer receives the requested raw or parsed header value");
        addOut(result, 4, NetworkOutParameterRole::BufferSize,
               NetworkOutParameterValidity::OnSuccessOrRequiredSize, true,
               "input buffer bytes, then bytes written or required");
        addOut(result, 5, NetworkOutParameterRole::QueryIndex,
               NetworkOutParameterValidity::OnSuccess, true,
               "enumeration index advances when matching headers are returned");
        return result;
    }
    if (key == "internetclosehandle") {
        return makeContract(
            NetworkReturnKind::Bool, NetworkReturnSuccessRule::NonZero,
            NetworkFailureSentinel::Zero, "BOOL",
            "TRUE: handle was invalidated; asynchronous callbacks may still finish",
            "FALSE: close failed; GetLastError supplies the reason",
            false, NetworkZeroResultMeaning::None, true);
    }

    if (oneOf(key, {"urldownloadtofile", "urldownloadtocachefile",
                    "urlopenstream", "urlopenpullstream",
                    "urlopenblockingstream"})) {
        auto result = makeContract(
            NetworkReturnKind::HResult,
            NetworkReturnSuccessRule::HResultSucceeded,
            NetworkFailureSentinel::FailedHResult, "HRESULT",
            "SUCCEEDED(hr): binding/download operation was accepted or completed",
            "FAILED(hr): COM/URL binding failure encoded in the HRESULT");
        if (key == "urldownloadtocachefile") {
            addOut(result, 3, NetworkOutParameterRole::CacheFilePath,
                   NetworkOutParameterValidity::OnSuccess, false,
                   "caller buffer receives the cache file path");
        } else if (key == "urlopenblockingstream") {
            addOut(result, 3, NetworkOutParameterRole::ComStream,
                   NetworkOutParameterValidity::OnSuccess, false,
                   "IStream pointer; caller releases the returned COM interface");
        }
        return result;
    }

    return std::nullopt;
}

} // namespace

const char* NetworkApiFamilyText(NetworkApiFamily family) {
    switch (family) {
    case NetworkApiFamily::Winsock: return "Winsock";
    case NetworkApiFamily::DnsApi:  return "DNS API";
    case NetworkApiFamily::WinHttp: return "WinHTTP";
    case NetworkApiFamily::WinInet: return "WinINet";
    case NetworkApiFamily::UrlMon:  return "URLMon";
    }
    return "Unknown";
}

const char* NetworkStageText(NetworkStage stage) {
    switch (stage) {
    case NetworkStage::Resolve: return "Resolve";
    case NetworkStage::Connect: return "Connect";
    case NetworkStage::Request: return "Request";
    case NetworkStage::Write:   return "Write";
    case NetworkStage::Read:    return "Read";
    case NetworkStage::Count:   break;
    }
    return "Unknown";
}

const char* NetworkReturnKindText(NetworkReturnKind kind) {
    switch (kind) {
    case NetworkReturnKind::Bool:            return "BOOL";
    case NetworkReturnKind::IntStatus:       return "integer status";
    case NetworkReturnKind::SignedByteCount: return "signed byte count";
    case NetworkReturnKind::SocketHandle:    return "SOCKET handle";
    case NetworkReturnKind::InternetHandle:  return "HINTERNET handle";
    case NetworkReturnKind::Pointer:         return "pointer";
    case NetworkReturnKind::HResult:         return "HRESULT";
    }
    return "unknown";
}

const char* NetworkReturnSuccessRuleText(NetworkReturnSuccessRule rule) {
    switch (rule) {
    case NetworkReturnSuccessRule::NonZero:         return "nonzero";
    case NetworkReturnSuccessRule::Zero:            return "zero";
    case NetworkReturnSuccessRule::NonNegative:     return "nonnegative";
    case NetworkReturnSuccessRule::NotInvalidSocket:return "not INVALID_SOCKET";
    case NetworkReturnSuccessRule::NonNull:         return "non-NULL";
    case NetworkReturnSuccessRule::HResultSucceeded:return "SUCCEEDED(hr)";
    }
    return "unknown";
}

const char* NetworkFailureSentinelText(NetworkFailureSentinel sentinel) {
    switch (sentinel) {
    case NetworkFailureSentinel::Zero:          return "FALSE (0)";
    case NetworkFailureSentinel::Null:          return "NULL";
    case NetworkFailureSentinel::SocketError:   return "SOCKET_ERROR (-1)";
    case NetworkFailureSentinel::InvalidSocket: return "INVALID_SOCKET";
    case NetworkFailureSentinel::NonZeroStatus: return "nonzero status";
    case NetworkFailureSentinel::FailedHResult: return "FAILED(hr)";
    }
    return "unknown";
}

const char* NetworkOutParameterRoleText(NetworkOutParameterRole role) {
    switch (role) {
    case NetworkOutParameterRole::AddressList:        return "address list";
    case NetworkOutParameterRole::SessionData:        return "session data";
    case NetworkOutParameterRole::HostEntry:          return "host entry";
    case NetworkOutParameterRole::HostText:           return "host text";
    case NetworkOutParameterRole::ServiceText:        return "service text";
    case NetworkOutParameterRole::SocketAddress:      return "socket address";
    case NetworkOutParameterRole::SocketAddressLength:return "socket address length";
    case NetworkOutParameterRole::ByteCount:          return "byte count";
    case NetworkOutParameterRole::PayloadBuffer:      return "payload buffer";
    case NetworkOutParameterRole::Flags:              return "flags";
    case NetworkOutParameterRole::ProxyInfo:          return "proxy information";
    case NetworkOutParameterRole::HeaderBuffer:       return "header buffer";
    case NetworkOutParameterRole::BufferSize:         return "buffer size";
    case NetworkOutParameterRole::QueryIndex:         return "query index";
    case NetworkOutParameterRole::DnsRecordList:      return "DNS record list";
    case NetworkOutParameterRole::CacheFilePath:      return "cache file path";
    case NetworkOutParameterRole::ComStream:          return "COM stream";
    case NetworkOutParameterRole::AsyncOperationHandle:return "asynchronous operation handle";
    }
    return "unknown";
}

const char* NetworkOutParameterValidityText(NetworkOutParameterValidity validity) {
    switch (validity) {
    case NetworkOutParameterValidity::OnSuccess: return "valid on success";
    case NetworkOutParameterValidity::OnSuccessOrAsyncCompletion:
        return "valid on success or asynchronous completion";
    case NetworkOutParameterValidity::OnSuccessOrRequiredSize:
        return "valid on success or required-size failure";
    case NetworkOutParameterValidity::OnAsyncPending:
        return "valid when asynchronous work is pending";
    }
    return "unknown";
}

const char* NetworkZeroResultMeaningText(NetworkZeroResultMeaning meaning) {
    switch (meaning) {
    case NetworkZeroResultMeaning::None: return "no special zero-result meaning";
    case NetworkZeroResultMeaning::EndOfStreamOrEmptyMessage:
        return "stream close or empty message";
    case NetworkZeroResultMeaning::EndOfBody:
        return "end of response/file body";
    }
    return "unknown";
}

const char* NetworkAsyncPendingRuleText(NetworkAsyncPendingRule rule) {
    switch (rule) {
    case NetworkAsyncPendingRule::None: return "not pending-capable";
    case NetworkAsyncPendingRule::LastErrorIoPending:
        return "ERROR_IO_PENDING from last-error state";
    case NetworkAsyncPendingRule::LastErrorNonblockingConnect:
        return "Winsock nonblocking-connect status from WSAGetLastError";
    case NetworkAsyncPendingRule::DirectStatusIoPending:
        return "WSA_IO_PENDING returned directly";
    }
    return "unknown";
}

const char* NetworkReturnDispositionText(NetworkReturnDisposition disposition) {
    switch (disposition) {
    case NetworkReturnDisposition::Success:       return "success";
    case NetworkReturnDisposition::Failure:       return "failure";
    case NetworkReturnDisposition::Indeterminate: return "pending/indeterminate";
    }
    return "unknown";
}

std::string NormalizeNetworkDll(std::string_view dll) {
    std::string out = trim(dll);
    const size_t bang = out.find('!');
    if (bang != std::string::npos) out.resize(bang);
    const size_t slash = out.find_last_of("/\\");
    if (slash != std::string::npos) out.erase(0, slash + 1);
    std::transform(out.begin(), out.end(), out.begin(), asciiLower);
    if (out.size() > 4 && out.compare(out.size() - 4, 4, ".dll") == 0)
        out.resize(out.size() - 4);
    return out;
}

std::string NormalizeNetworkApiName(std::string_view symbol) {
    std::string out = trim(symbol);
    if (const size_t bang = out.rfind('!'); bang != std::string::npos)
        out.erase(0, bang + 1);
    std::transform(out.begin(), out.end(), out.begin(), asciiLower);

    constexpr std::string_view prefixes[] = {
        "__imp__", "__imp_", "_imp__", "_imp_", "imp_"
    };
    bool stripped = true;
    while (stripped) {
        stripped = false;
        for (const std::string_view prefix : prefixes) {
            if (out.size() >= prefix.size() &&
                out.compare(0, prefix.size(), prefix) == 0) {
                out.erase(0, prefix.size());
                stripped = true;
                break;
            }
        }
    }
    while (!out.empty() && (out.front() == '_' || out.front() == '@'))
        out.erase(out.begin());

    if (const size_t at = out.rfind('@'); at != std::string::npos &&
        allDigits(std::string_view(out).substr(at + 1)))
        out.resize(at);

    // A/W is part of the Windows ABI decoration only when the undecorated base
    // is itself an exact catalog key.  SendMessageW therefore remains intact.
    constexpr std::string_view underscoredSuffixes[] = { "_utf8", "_a", "_w" };
    for (const std::string_view suffix : underscoredSuffixes) {
        if (out.size() > suffix.size() && out.ends_with(suffix)) {
            const std::string_view base(out.data(), out.size() - suffix.size());
            if (rowByKey(base)) {
                out.resize(out.size() - suffix.size());
                return out;
            }
        }
    }
    if (out.size() > 1 && (out.back() == 'a' || out.back() == 'w')) {
        const std::string_view base(out.data(), out.size() - 1);
        if (rowByKey(base)) out.resize(out.size() - 1);
    }
    return out;
}

std::optional<NetworkApiMatch> LookupNetworkApi(std::string_view dll,
                                                std::string_view symbol) {
    std::string module = NormalizeNetworkDll(dll);
    if (const size_t bang = symbol.rfind('!'); bang != std::string_view::npos) {
        const std::string qualifiedModule = NormalizeNetworkDll(symbol.substr(0, bang));
        if (module.empty()) module = qualifiedModule;
        else if (!qualifiedModule.empty() && module != qualifiedModule) return std::nullopt;
    }
    if (module.empty()) return std::nullopt;

    const std::string name = NormalizeNetworkApiName(symbol);
    for (const CatalogRow& row : kCatalog) {
        if (module == row.dll && name == row.key) {
            NetworkApiMatch match;
            match.family = row.family;
            match.stage = row.stage;
            match.dll = module;
            match.canonicalName = row.canonical;
            match.normalizedName = name;
            match.lifecycle = row.lifecycle;
            return match;
        }
    }
    return std::nullopt;
}

std::optional<NetworkApiReturnContract>
LookupNetworkApiReturnContract(std::string_view dll, std::string_view symbol) {
    const std::optional<NetworkApiMatch> match = LookupNetworkApi(dll, symbol);
    if (!match) return std::nullopt;
    return contractFor(*match);
}

bool NetworkReturnIsImmediateSuccess(const NetworkApiReturnContract& contract,
                                     uint64_t rawValue,
                                     uint8_t pointerWidthBits) {
    const uint32_t low32 = static_cast<uint32_t>(rawValue);
    const int32_t signed32 = static_cast<int32_t>(low32);
    const uint64_t pointerMask = pointerWidthBits == 32
        ? UINT64_C(0xFFFFFFFF)
        : UINT64_MAX;
    const uint64_t pointerValue = rawValue & pointerMask;

    switch (contract.successRule) {
    case NetworkReturnSuccessRule::NonZero:
        return low32 != 0;
    case NetworkReturnSuccessRule::Zero:
        return low32 == 0;
    case NetworkReturnSuccessRule::NonNegative:
        return signed32 >= 0;
    case NetworkReturnSuccessRule::NotInvalidSocket:
        return pointerValue != pointerMask;
    case NetworkReturnSuccessRule::NonNull:
        return pointerValue != 0;
    case NetworkReturnSuccessRule::HResultSucceeded:
        return signed32 >= 0;
    }
    return false;
}

NetworkReturnDisposition InterpretNetworkApiReturn(
    const NetworkApiReturnContract& contract,
    uint64_t rawValue,
    std::optional<uint32_t> errorCode,
    uint8_t pointerWidthBits) {
    if (NetworkReturnIsImmediateSuccess(contract, rawValue, pointerWidthBits))
        return NetworkReturnDisposition::Success;
    if (!contract.asyncPendingPossible)
        return NetworkReturnDisposition::Failure;

    constexpr uint32_t kErrorIoPending = 997;
    constexpr uint32_t kWsaWouldBlock = 10035;
    constexpr uint32_t kWsaInProgress = 10036;
    constexpr uint32_t kWsaAlready = 10037;

    switch (contract.pendingRule) {
    case NetworkAsyncPendingRule::None:
        return NetworkReturnDisposition::Failure;
    case NetworkAsyncPendingRule::DirectStatusIoPending:
        return static_cast<uint32_t>(rawValue) == kErrorIoPending
            ? NetworkReturnDisposition::Indeterminate
            : NetworkReturnDisposition::Failure;
    case NetworkAsyncPendingRule::LastErrorIoPending:
        if (!errorCode) return NetworkReturnDisposition::Indeterminate;
        return *errorCode == kErrorIoPending
            ? NetworkReturnDisposition::Indeterminate
            : NetworkReturnDisposition::Failure;
    case NetworkAsyncPendingRule::LastErrorNonblockingConnect:
        if (!errorCode) return NetworkReturnDisposition::Indeterminate;
        return *errorCode == kWsaWouldBlock || *errorCode == kWsaInProgress ||
               *errorCode == kWsaAlready
            ? NetworkReturnDisposition::Indeterminate
            : NetworkReturnDisposition::Failure;
    }
    return NetworkReturnDisposition::Failure;
}

std::vector<NetworkApiMatch> EnumerateNetworkApis() {
    std::vector<NetworkApiMatch> result;
    result.reserve(std::size(kCatalog));
    for (const CatalogRow& row : kCatalog) {
        NetworkApiMatch match;
        match.family = row.family;
        match.stage = row.stage;
        match.dll = row.dll;
        match.canonicalName = row.canonical;
        match.normalizedName = row.key;
        match.lifecycle = row.lifecycle;
        result.push_back(std::move(match));
    }
    return result;
}

} // namespace ds
