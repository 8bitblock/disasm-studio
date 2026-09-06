#pragma once

// Deterministic local HTTP peer used by both x64_debug_test and the disposable
// x86 target built by wow64_debug_test. No request leaves the loopback adapter.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <wininet.h>

#include <cstdint>
#include <cstring>
#include <string>

namespace ds::testfixture {

struct LocalHttpPeer {
    SOCKET listener = INVALID_SOCKET;
    const char* expectedRequest = nullptr;
    const char* expectedBody = nullptr;
    const char* responseBody = nullptr;
};

inline DWORD WINAPI LocalHttpReplyWorker(void* parameter) {
    auto* peerState = static_cast<LocalHttpPeer*>(parameter);
    const SOCKET peer = accept(peerState->listener, nullptr, nullptr);
    if (peer == INVALID_SOCKET) return 1;

    std::string request;
    char chunk[1024]{};
    while (request.size() < 16u * 1024u) {
        const int received = recv(peer, chunk, static_cast<int>(sizeof(chunk)), 0);
        if (received <= 0) break;
        request.append(chunk, chunk + received);
        if (request.find("\r\n\r\n") != std::string::npos &&
            peerState->expectedBody &&
            request.find(peerState->expectedBody) != std::string::npos)
            break;
    }

    const std::string body = peerState->responseBody ? peerState->responseBody : "";
    const std::string response =
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
        std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    size_t sent = 0;
    while (sent < response.size()) {
        const int wrote = send(peer, response.data() + sent,
                               static_cast<int>(response.size() - sent), 0);
        if (wrote <= 0) break;
        sent += static_cast<size_t>(wrote);
    }
    shutdown(peer, SD_BOTH);
    closesocket(peer);
    return peerState->expectedRequest && peerState->expectedBody &&
           request.find(peerState->expectedRequest) != std::string::npos &&
           request.find(peerState->expectedBody) != std::string::npos &&
           sent == response.size() ? 0 : 2;
}

// Exercise BOOL-returning HTTP APIs with invalid handles and deliberately
// non-zero completion sentinels. The observer may retain requested input, but
// must not present any completion-owned count/buffer as transferred on failure.
inline bool RunExpectedFailedBooleanIo() {
    char winHttpBody[] = "failed-winhttp-inline";
    const bool winHttpFailed = WinHttpSendRequest(
        nullptr, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        winHttpBody, static_cast<DWORD>(sizeof(winHttpBody) - 1),
        static_cast<DWORD>(sizeof(winHttpBody) - 1), 0) == FALSE;

    char winInetBody[] = "failed-wininet-inline";
    const bool winInetFailed = HttpSendRequestW(
        nullptr, nullptr, 0, winInetBody,
        static_cast<DWORD>(sizeof(winInetBody) - 1)) == FALSE;

    DWORD winHttpWritten = 0xA5A5A5A5u;
    char winHttpWriteBody[] = "failed-winhttp-write";
    const bool winHttpWriteFailed = WinHttpWriteData(
        nullptr, winHttpWriteBody, static_cast<DWORD>(sizeof(winHttpWriteBody) - 1),
        &winHttpWritten) == FALSE;
    DWORD winInetWritten = 0xB6B6B6B6u;
    char winInetWriteBody[] = "failed-wininet-write";
    const bool winInetWriteFailed = InternetWriteFile(
        nullptr, winInetWriteBody, static_cast<DWORD>(sizeof(winInetWriteBody) - 1),
        &winInetWritten) == FALSE;

    char winHttpReadBuffer[17];
    std::memset(winHttpReadBuffer, 0xC7, sizeof(winHttpReadBuffer));
    DWORD winHttpRead = 0xC7C7C7C7u;
    const bool winHttpReadFailed = WinHttpReadData(
        nullptr, winHttpReadBuffer, static_cast<DWORD>(sizeof(winHttpReadBuffer)),
        &winHttpRead) == FALSE;
    char winInetReadBuffer[19];
    std::memset(winInetReadBuffer, 0xD8, sizeof(winInetReadBuffer));
    DWORD winInetRead = 0xD8D8D8D8u;
    const bool winInetReadFailed = InternetReadFile(
        nullptr, winInetReadBuffer, static_cast<DWORD>(sizeof(winInetReadBuffer)),
        &winInetRead) == FALSE;

    char winInetReadExBuffer[23];
    std::memset(winInetReadExBuffer, 0xE9, sizeof(winInetReadExBuffer));
    INTERNET_BUFFERSW readEx{};
    readEx.dwStructSize = sizeof(readEx);
    readEx.lpvBuffer = winInetReadExBuffer;
    readEx.dwBufferLength = static_cast<DWORD>(sizeof(winInetReadExBuffer));
    const bool winInetReadExFailed = InternetReadFileExW(nullptr, &readEx, 0, 0) == FALSE;

    char winHttpQueryBuffer[29];
    std::memset(winHttpQueryBuffer, 0xFA, sizeof(winHttpQueryBuffer));
    DWORD winHttpQueryBytes = static_cast<DWORD>(sizeof(winHttpQueryBuffer));
    const bool winHttpQueryFailed = WinHttpQueryHeaders(
        nullptr, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
        winHttpQueryBuffer, &winHttpQueryBytes, WINHTTP_NO_HEADER_INDEX) == FALSE;
    char winInetQueryBuffer[31];
    std::memset(winInetQueryBuffer, 0x8B, sizeof(winInetQueryBuffer));
    DWORD winInetQueryBytes = static_cast<DWORD>(sizeof(winInetQueryBuffer));
    const bool winInetQueryFailed = HttpQueryInfoW(
        nullptr, HTTP_QUERY_RAW_HEADERS_CRLF, winInetQueryBuffer,
        &winInetQueryBytes, nullptr) == FALSE;

    return winHttpFailed && winInetFailed && winHttpWriteFailed &&
           winInetWriteFailed && winHttpReadFailed && winInetReadFailed &&
           winInetReadExFailed && winHttpQueryFailed && winInetQueryFailed;
}

inline bool RunLocalWinHttpExchange() {
    LocalHttpPeer peerState;
    peerState.expectedRequest = "POST /serial-check ";
    peerState.expectedBody = "serial=crackme-query";
    peerState.responseBody = "hosted-http-reply:accepted";
    peerState.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (peerState.listener == INVALID_SOCKET) return false;
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(peerState.listener, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) ==
            SOCKET_ERROR ||
        listen(peerState.listener, 1) == SOCKET_ERROR) {
        closesocket(peerState.listener);
        return false;
    }
    int localLength = sizeof(local);
    if (getsockname(peerState.listener, reinterpret_cast<sockaddr*>(&local), &localLength) ==
        SOCKET_ERROR) {
        closesocket(peerState.listener);
        return false;
    }
    HANDLE worker = CreateThread(nullptr, 0, LocalHttpReplyWorker, &peerState, 0, nullptr);
    if (!worker) {
        closesocket(peerState.listener);
        return false;
    }

    HINTERNET session = WinHttpOpen(L"DisasmStudioNetworkFixture/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connection = session ? WinHttpConnect(session, L"127.0.0.1",
        static_cast<INTERNET_PORT>(ntohs(local.sin_port)), 0) : nullptr;
    HINTERNET request = connection ? WinHttpOpenRequest(connection, L"POST",
        L"/serial-check", nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0) : nullptr;

    char requestBody[] = "serial=crackme-query";
    bool httpOk = request && WinHttpSendRequest(request,
        L"Content-Type: application/x-www-form-urlencoded\r\n", static_cast<DWORD>(-1),
        requestBody, static_cast<DWORD>(sizeof(requestBody) - 1),
        static_cast<DWORD>(sizeof(requestBody) - 1), 0) != FALSE;
    httpOk = httpOk && WinHttpReceiveResponse(request, nullptr) != FALSE;

    std::string responseBody;
    if (httpOk) {
        for (;;) {
            char responseChunk[64]{};
            DWORD received = 0;
            if (!WinHttpReadData(request, responseChunk,
                                 static_cast<DWORD>(sizeof(responseChunk)), &received)) {
                httpOk = false;
                break;
            }
            if (!received) break;
            responseBody.append(responseChunk, responseChunk + received);
            if (responseBody.size() > 1024) { httpOk = false; break; }
        }
    }

    if (request) WinHttpCloseHandle(request);
    if (connection) WinHttpCloseHandle(connection);
    if (session) WinHttpCloseHandle(session);
    WaitForSingleObject(worker, 5000);
    DWORD workerResult = 99;
    (void)GetExitCodeThread(worker, &workerResult);
    CloseHandle(worker);
    closesocket(peerState.listener);
    return httpOk && workerResult == 0 && responseBody == "hosted-http-reply:accepted";
}

inline bool RunLocalWinInetExchange() {
    LocalHttpPeer peerState;
    peerState.expectedRequest = "POST /wininet-check ";
    peerState.expectedBody = "serial=wininet-query";
    peerState.responseBody = "hosted-wininet-reply:accepted";
    peerState.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (peerState.listener == INVALID_SOCKET) return false;
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(peerState.listener, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) ==
            SOCKET_ERROR ||
        listen(peerState.listener, 1) == SOCKET_ERROR) {
        closesocket(peerState.listener);
        return false;
    }
    int localLength = sizeof(local);
    if (getsockname(peerState.listener, reinterpret_cast<sockaddr*>(&local), &localLength) ==
        SOCKET_ERROR) {
        closesocket(peerState.listener);
        return false;
    }
    HANDLE worker = CreateThread(nullptr, 0, LocalHttpReplyWorker, &peerState, 0, nullptr);
    if (!worker) {
        closesocket(peerState.listener);
        return false;
    }

    HINTERNET session = InternetOpenW(L"DisasmStudioNetworkFixture/1.0",
        INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    HINTERNET connection = session ? InternetConnectW(session, L"127.0.0.1",
        static_cast<INTERNET_PORT>(ntohs(local.sin_port)), nullptr, nullptr,
        INTERNET_SERVICE_HTTP, 0, 0) : nullptr;
    const wchar_t* acceptTypes[] = {L"text/plain", nullptr};
    HINTERNET request = connection ? HttpOpenRequestW(connection, L"POST",
        L"/wininet-check", nullptr, nullptr, acceptTypes,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0) : nullptr;

    char requestBody[] = "serial=wininet-query";
    bool httpOk = request && HttpSendRequestW(request,
        L"Content-Type: application/x-www-form-urlencoded\r\n", static_cast<DWORD>(-1),
        requestBody, static_cast<DWORD>(sizeof(requestBody) - 1)) != FALSE;
    std::string responseBody;
    if (httpOk) {
        for (;;) {
            char responseChunk[64]{};
            DWORD received = 0;
            if (!InternetReadFile(request, responseChunk,
                                  static_cast<DWORD>(sizeof(responseChunk)), &received)) {
                httpOk = false;
                break;
            }
            if (!received) break;
            responseBody.append(responseChunk, responseChunk + received);
            if (responseBody.size() > 1024) { httpOk = false; break; }
        }
    }

    if (request) InternetCloseHandle(request);
    if (connection) InternetCloseHandle(connection);
    if (session) InternetCloseHandle(session);
    WaitForSingleObject(worker, 5000);
    DWORD workerResult = 99;
    (void)GetExitCodeThread(worker, &workerResult);
    CloseHandle(worker);
    closesocket(peerState.listener);
    return httpOk && workerResult == 0 &&
           responseBody == "hosted-wininet-reply:accepted";
}

} // namespace ds::testfixture
