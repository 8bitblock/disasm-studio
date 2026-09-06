// Tiny architecture-neutral local hosted-reply fixture. wow64_debug_test builds
// this source with the VS x86 compiler at runtime, then launches it under the
// x64 debugger. It intentionally has no public-network dependency.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstring>

#include "network_http_fixture.h"

static DWORD WINAPI replyWorker(void* parameter) {
    const SOCKET listener = static_cast<SOCKET>(reinterpret_cast<uintptr_t>(parameter));
    const SOCKET peer = accept(listener, nullptr, nullptr);
    if (peer == INVALID_SOCKET) return 1;
    char request[64]{};
    const int received = recv(peer, request, static_cast<int>(sizeof(request)), 0);
    static constexpr char reply[] = "hosted-reply:accepted";
    if (received > 0)
        (void)send(peer, reply, static_cast<int>(sizeof(reply) - 1), 0);
    closesocket(peer);
    return received > 0 ? 0 : 2;
}

int main() {
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return 10;
    const SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) { WSACleanup(); return 11; }
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) == SOCKET_ERROR ||
        listen(listener, 1) == SOCKET_ERROR) {
        closesocket(listener); WSACleanup(); return 12;
    }
    int localLength = sizeof(local);
    if (getsockname(listener, reinterpret_cast<sockaddr*>(&local), &localLength) == SOCKET_ERROR) {
        closesocket(listener); WSACleanup(); return 13;
    }
    HANDLE worker = CreateThread(nullptr, 0, replyWorker,
        reinterpret_cast<void*>(static_cast<uintptr_t>(listener)), 0, nullptr);
    if (!worker) { closesocket(listener); WSACleanup(); return 14; }

    char service[16]{};
    std::snprintf(service, sizeof(service), "%u", static_cast<unsigned>(ntohs(local.sin_port)));
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* addresses = nullptr;
    const int resolved = getaddrinfo("localhost", service, &hints, &addresses);
    SOCKET client = INVALID_SOCKET;
    if (resolved == 0) {
        for (addrinfo* it = addresses; it; it = it->ai_next) {
            client = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
            if (client != INVALID_SOCKET &&
                connect(client, it->ai_addr, static_cast<int>(it->ai_addrlen)) == 0)
                break;
            if (client != INVALID_SOCKET) closesocket(client);
            client = INVALID_SOCKET;
        }
    }

    static constexpr char request[] = "crackme-query:serial";
    char reply[64]{};
    int replyLength = SOCKET_ERROR;
    if (client != INVALID_SOCKET &&
        send(client, request, static_cast<int>(sizeof(request) - 1), 0) > 0)
        replyLength = recv(client, reply, static_cast<int>(sizeof(reply)), 0);

    if (addresses) freeaddrinfo(addresses);
    if (client != INVALID_SOCKET) closesocket(client);
    WaitForSingleObject(worker, 5000);
    DWORD workerResult = 99;
    (void)GetExitCodeThread(worker, &workerResult);
    CloseHandle(worker);
    closesocket(listener);
    const bool rawOk = resolved == 0 && replyLength > 0 && workerResult == 0 &&
        replyLength == static_cast<int>(sizeof("hosted-reply:accepted") - 1) &&
        std::memcmp(reply, "hosted-reply:accepted", sizeof("hosted-reply:accepted") - 1) == 0;
    const bool failedBooleanSendsOk = ds::testfixture::RunExpectedFailedBooleanIo();
    const bool winHttpOk = ds::testfixture::RunLocalWinHttpExchange();
    const bool winInetOk = ds::testfixture::RunLocalWinInetExchange();
    WSACleanup();
    Sleep(750);
    return rawOk && failedBooleanSendsOk && winHttpOk && winInetOk ? 0 : 15;
}
