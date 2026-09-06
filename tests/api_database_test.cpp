#include "Core/ApiDatabase.h"

#include <cstdio>
#include <string>

using namespace ds;

static int failures = 0;
#define CHECK(x) do { if (!(x)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); ++failures; \
} } while (0)

static bool has(const std::string& value, const char* part) {
    return value.find(part) != std::string::npos;
}

int main() {
    const ApiPrototypeInfo* create = FindWindowsApiPrototype("KERNEL32.dll!CreateFileW");
    CHECK(create != nullptr);
    CHECK(create && create->parameterCount == 7);
    CHECK(create && create->parameters[1].name == "desiredAccess");
    CHECK(create && create->parameters[4].valueDomain == ApiValueDomain::CreationDisposition);
    CHECK(FindWindowsApiPrototype("_CreateFileA@28") == create);
    CHECK(FindWindowsApiPrototype("totally_unknown") == nullptr);

    const ApiPrototypeInfo* whConnect =
        FindWindowsApiPrototype("WINHTTP!WinHttpConnect");
    CHECK(whConnect != nullptr);
    CHECK(whConnect && whConnect->parameterCount == 4);
    CHECK(whConnect && whConnect->parameters[1].name == "serverName");
    CHECK(whConnect && whConnect->parameters[2].name == "serverPort");
    const ApiPrototypeInfo* whRequest =
        FindWindowsApiPrototype("WinHttpOpenRequest");
    CHECK(whRequest != nullptr);
    CHECK(whRequest && whRequest->parameters[2].name == "objectName");
    const ApiPrototypeInfo* inetConnect =
        FindWindowsApiPrototype("wininet!InternetConnectW");
    CHECK(inetConnect != nullptr);
    CHECK(inetConnect && inetConnect->parameterCount == 8);
    CHECK(inetConnect && inetConnect->parameters[1].name == "serverName");
    CHECK(inetConnect && inetConnect->parameters[2].name == "serverPort");
    CHECK(FindWindowsApiPrototype("ws2_32!WSAConnect") != nullptr);
    CHECK(FindWindowsApiPrototype("user32!SendMessageW") == nullptr);

    struct ExpectedPrototype {
        const char* name;
        uint8_t count;
        uint8_t namedIndex;
        const char* parameter;
    };
    const ExpectedPrototype networkPrototypes[] = {
        { "ws2_32!GetAddrInfoExW", 10, 0, "name" },
        { "ws2_32!gethostbyname", 1, 0, "name" },
        { "ws2_32!gethostbyaddr", 3, 0, "address" },
        { "ws2_32!getnameinfo", 7, 2, "host" },
        { "dnsapi!DnsQuery_UTF8", 6, 0, "name" },
        { "ws2_32!WSASendTo", 9, 5, "to" },
        { "ws2_32!WSARecvFrom", 9, 5, "from" },
        { "winhttp!WinHttpAddRequestHeaders", 4, 1, "headers" },
        { "winhttp!WinHttpSetCredentials", 6, 3, "userName" },
        { "wininet!HttpAddRequestHeadersW", 4, 1, "headers" },
        { "wininet!InternetOpenUrlA", 6, 1, "url" },
        { "wininet!HttpSendRequestExW", 5, 1, "buffersIn" },
        { "wininet!HttpEndRequestA", 4, 1, "buffersOut" },
        { "wininet!InternetReadFileExW", 4, 1, "buffersOut" },
        { "urlmon!URLDownloadToCacheFileW", 6, 1, "url" },
        { "urlmon!URLOpenStreamA", 4, 1, "url" },
        { "urlmon!URLOpenPullStreamW", 4, 1, "url" },
        { "urlmon!URLOpenBlockingStreamW", 5, 1, "url" },
        { "ws2_32!AcceptEx", 8, 1, "acceptSocket" },
        { "ws2_32!closesocket", 1, 0, "socket" },
        { "winhttp!WinHttpCloseHandle", 1, 0, "handle" },
        { "wininet!InternetCloseHandle", 1, 0, "handle" },
    };
    for (const ExpectedPrototype& expected : networkPrototypes) {
        const ApiPrototypeInfo* found = FindWindowsApiPrototype(expected.name);
        CHECK(found != nullptr);
        CHECK(found && found->parameterCount == expected.count);
        CHECK(found && expected.namedIndex < found->parameterCount &&
              found->parameters[expected.namedIndex].name == expected.parameter);
    }
    CHECK(FindWindowsApiPrototype("dnsapi!DnsQuery_A") ==
          FindWindowsApiPrototype("dnsapi!DnsQuery_W"));
    CHECK(FindWindowsApiPrototype("ws2_32!WSACleanup") != nullptr);
    CHECK(FindWindowsApiPrototype("ws2_32!WSACleanup")->parameterCount == 0);

    CHECK(FormatApiConstant(ApiValueDomain::Boolean, 0) == "FALSE");
    CHECK(FormatApiConstant(ApiValueDomain::Boolean, 1) == "TRUE");
    CHECK(FormatApiConstant(ApiValueDomain::CreationDisposition, 3) == "OPEN_EXISTING");
    CHECK(FormatApiConstant(ApiValueDomain::PageProtection, 0x40) == "PAGE_EXECUTE_READWRITE");
    CHECK(FormatApiConstant(ApiValueDomain::PageProtection, 0x104) ==
          "PAGE_READWRITE | PAGE_GUARD");
    CHECK(FormatApiConstant(ApiValueDomain::AllocationType, 0x3000) ==
          "MEM_COMMIT | MEM_RESERVE");
    CHECK(FormatApiConstant(ApiValueDomain::GenericAccess, 0xC0000000) ==
          "GENERIC_READ | GENERIC_WRITE");
    CHECK(has(FormatApiConstant(ApiValueDomain::ProcessAccess, 0x38), "PROCESS_VM_OPERATION"));
    CHECK(has(FormatApiConstant(ApiValueDomain::ProcessAccess, 0x38), "PROCESS_VM_READ"));
    CHECK(has(FormatApiConstant(ApiValueDomain::ProcessAccess, 0x38), "PROCESS_VM_WRITE"));
    CHECK(FormatApiConstant(ApiValueDomain::SocketFamily, 23) == "AF_INET6");
    CHECK(FormatApiConstant(ApiValueDomain::SocketType, 1) == "SOCK_STREAM");
    CHECK(FormatApiConstant(ApiValueDomain::SocketProtocol, 6) == "IPPROTO_TCP");
    CHECK(FormatApiConstant(ApiValueDomain::WaitMilliseconds, 0xFFFFFFFF) == "INFINITE");
    CHECK(FormatApiConstant(ApiValueDomain::WaitMilliseconds, 1000).empty());

    CHECK(FormatWindowsApiArgument("CreateFileW", 1, 0xC0000000) ==
          "desiredAccess=GENERIC_READ | GENERIC_WRITE");
    CHECK(FormatWindowsApiArgument("VirtualAlloc", 2, 0x3000) ==
          "allocationType=MEM_COMMIT | MEM_RESERVE");
    CHECK(FormatWindowsApiArgument("VirtualAlloc", 3, 0x40) ==
          "protection=PAGE_EXECUTE_READWRITE");
    CHECK(FormatWindowsApiArgument("VirtualAlloc", 9, 0).empty());
    CHECK(FormatWindowsApiArgument("unknown", 0, 0).empty());

    const std::string prototype = FormatWindowsApiPrototype("kernel32.CreateFileA");
    CHECK(has(prototype, "HANDLE createfile("));
    CHECK(has(prototype, "DWORD desiredAccess"));
    CHECK(has(prototype, "HANDLE templateFile?"));
    const ApiPrototypeInfo* exit = FindWindowsApiPrototype("ExitProcess");
    CHECK(exit && exit->noreturn);

    if (!failures) std::printf("api_database_test: all checks passed\n");
    return failures ? 1 : 0;
}
