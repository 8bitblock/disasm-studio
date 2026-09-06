#pragma once
//
// ApiDatabase.h
// A deliberately bounded, dependency-free Windows API prototype/constant
// database. It is not a replacement for PDB types: it covers a compact set of
// high-value APIs so annotations can name recovered arguments and render common
// access/protection/creation values symbolically. Unknown APIs and values remain
// explicit rather than being guessed.
//
#include <array>
#include <charconv>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace ds {

enum class ApiValueDomain : uint8_t {
    None = 0,
    Boolean,
    GenericAccess,
    FileShare,
    CreationDisposition,
    FileAttributes,
    PageProtection,
    AllocationType,
    ProcessAccess,
    ThreadAccess,
    RegistryAccess,
    SocketFamily,
    SocketType,
    SocketProtocol,
    MessageBoxFlags,
    WaitMilliseconds,
};

struct ApiParameterInfo {
    std::string_view type;
    std::string_view name;
    ApiValueDomain   valueDomain = ApiValueDomain::None;
    bool             output = false;
    bool             optional = false;
};

struct ApiPrototypeInfo {
    std::string_view canonicalName;
    std::string_view returnType;
    const ApiParameterInfo* parameters = nullptr;
    uint8_t parameterCount = 0;
    bool noreturn = false;
};

namespace api_database_detail {

using D = ApiValueDomain;
using P = ApiParameterInfo;

inline constexpr P kCreateFile[] = {
    {"LPCWSTR", "fileName"}, {"DWORD", "desiredAccess", D::GenericAccess},
    {"DWORD", "shareMode", D::FileShare}, {"LPSECURITY_ATTRIBUTES", "security", D::None, false, true},
    {"DWORD", "creationDisposition", D::CreationDisposition},
    {"DWORD", "flagsAndAttributes", D::FileAttributes}, {"HANDLE", "templateFile", D::None, false, true},
};
inline constexpr P kReadWriteFile[] = {
    {"HANDLE", "file"}, {"LPVOID", "buffer", D::None, true}, {"DWORD", "bytesRequested"},
    {"LPDWORD", "bytesTransferred", D::None, true, true},
    {"LPOVERLAPPED", "overlapped", D::None, false, true},
};
inline constexpr P kVirtualAlloc[] = {
    {"LPVOID", "address", D::None, false, true}, {"SIZE_T", "size"},
    {"DWORD", "allocationType", D::AllocationType}, {"DWORD", "protection", D::PageProtection},
};
inline constexpr P kVirtualAllocEx[] = {
    {"HANDLE", "process"}, {"LPVOID", "address", D::None, false, true}, {"SIZE_T", "size"},
    {"DWORD", "allocationType", D::AllocationType}, {"DWORD", "protection", D::PageProtection},
};
inline constexpr P kVirtualProtect[] = {
    {"LPVOID", "address"}, {"SIZE_T", "size"}, {"DWORD", "newProtection", D::PageProtection},
    {"PDWORD", "oldProtection", D::None, true},
};
inline constexpr P kVirtualProtectEx[] = {
    {"HANDLE", "process"}, {"LPVOID", "address"}, {"SIZE_T", "size"},
    {"DWORD", "newProtection", D::PageProtection}, {"PDWORD", "oldProtection", D::None, true},
};
inline constexpr P kOpenProcess[] = {
    {"DWORD", "desiredAccess", D::ProcessAccess}, {"BOOL", "inheritHandle", D::Boolean},
    {"DWORD", "processId"},
};
inline constexpr P kOpenThread[] = {
    {"DWORD", "desiredAccess", D::ThreadAccess}, {"BOOL", "inheritHandle", D::Boolean},
    {"DWORD", "threadId"},
};
inline constexpr P kCreateRemoteThread[] = {
    {"HANDLE", "process"}, {"LPSECURITY_ATTRIBUTES", "threadAttributes", D::None, false, true},
    {"SIZE_T", "stackSize"}, {"LPTHREAD_START_ROUTINE", "startAddress"},
    {"LPVOID", "parameter", D::None, false, true}, {"DWORD", "creationFlags"},
    {"LPDWORD", "threadId", D::None, true, true},
};
inline constexpr P kCreateProcess[] = {
    {"LPCWSTR", "applicationName", D::None, false, true}, {"LPWSTR", "commandLine", D::None, false, true},
    {"LPSECURITY_ATTRIBUTES", "processAttributes", D::None, false, true},
    {"LPSECURITY_ATTRIBUTES", "threadAttributes", D::None, false, true},
    {"BOOL", "inheritHandles", D::Boolean}, {"DWORD", "creationFlags"},
    {"LPVOID", "environment", D::None, false, true}, {"LPCWSTR", "currentDirectory", D::None, false, true},
    {"LPSTARTUPINFOW", "startupInfo"}, {"LPPROCESS_INFORMATION", "processInformation", D::None, true},
};
inline constexpr P kProcessMemory[] = {
    {"HANDLE", "process"}, {"LPCVOID", "baseAddress"}, {"LPVOID", "buffer", D::None, true},
    {"SIZE_T", "size"}, {"SIZE_T*", "bytesTransferred", D::None, true, true},
};
inline constexpr P kRegOpenKeyEx[] = {
    {"HKEY", "key"}, {"LPCWSTR", "subKey", D::None, false, true}, {"DWORD", "options"},
    {"REGSAM", "desiredAccess", D::RegistryAccess}, {"PHKEY", "result", D::None, true},
};
inline constexpr P kRegCreateKeyEx[] = {
    {"HKEY", "key"}, {"LPCWSTR", "subKey"}, {"DWORD", "reserved"},
    {"LPWSTR", "className", D::None, false, true}, {"DWORD", "options"},
    {"REGSAM", "desiredAccess", D::RegistryAccess},
    {"LPSECURITY_ATTRIBUTES", "security", D::None, false, true},
    {"PHKEY", "result", D::None, true}, {"LPDWORD", "disposition", D::None, true, true},
};
inline constexpr P kRegSetValueEx[] = {
    {"HKEY", "key"}, {"LPCWSTR", "valueName", D::None, false, true}, {"DWORD", "reserved"},
    {"DWORD", "type"}, {"const BYTE*", "data"}, {"DWORD", "dataSize"},
};
inline constexpr P kSocket[] = {
    {"int", "addressFamily", D::SocketFamily}, {"int", "socketType", D::SocketType},
    {"int", "protocol", D::SocketProtocol},
};
inline constexpr P kConnect[] = {
    {"SOCKET", "socket"}, {"const sockaddr*", "address"}, {"int", "addressLength"},
};
inline constexpr P kAccept[] = {
    {"SOCKET", "socket"}, {"sockaddr*", "address", D::None, true, true},
    {"int*", "addressLength", D::None, true, true},
};
inline constexpr P kAcceptEx[] = {
    {"SOCKET", "listenSocket"}, {"SOCKET", "acceptSocket"},
    {"PVOID", "outputBuffer", D::None, true}, {"DWORD", "receiveDataLength"},
    {"DWORD", "localAddressLength"}, {"DWORD", "remoteAddressLength"},
    {"LPDWORD", "bytesReceived", D::None, true}, {"LPOVERLAPPED", "overlapped"},
};
inline constexpr P kConnectEx[] = {
    {"SOCKET", "socket"}, {"const sockaddr*", "address"}, {"int", "addressLength"},
    {"PVOID", "sendBuffer", D::None, false, true}, {"DWORD", "sendDataLength"},
    {"LPDWORD", "bytesSent", D::None, true, true}, {"LPOVERLAPPED", "overlapped"},
};
inline constexpr P kWsaConnect[] = {
    {"SOCKET", "socket"}, {"const sockaddr*", "address"}, {"int", "addressLength"},
    {"LPWSABUF", "callerData", D::None, false, true},
    {"LPWSABUF", "calleeData", D::None, true, true},
    {"LPQOS", "sendQos", D::None, false, true},
    {"LPQOS", "groupQos", D::None, false, true},
};
inline constexpr P kWsaSocket[] = {
    {"int", "addressFamily", D::SocketFamily}, {"int", "socketType", D::SocketType},
    {"int", "protocol", D::SocketProtocol},
    {"LPWSAPROTOCOL_INFO", "protocolInfo", D::None, false, true},
    {"GROUP", "group"}, {"DWORD", "flags"},
};
inline constexpr P kWsaStartup[] = {
    {"WORD", "versionRequested"}, {"LPWSADATA", "wsaData", D::None, true},
};
inline constexpr P kOneSocket[] = {{"SOCKET", "socket"}};
inline constexpr P kSocketBuffer[] = {
    {"SOCKET", "socket"}, {"void*", "buffer"}, {"int", "length"}, {"int", "flags"},
};
inline constexpr P kSocketSendTo[] = {
    {"SOCKET", "socket"}, {"const void*", "buffer"}, {"int", "length"}, {"int", "flags"},
    {"const sockaddr*", "to"}, {"int", "toLength"},
};
inline constexpr P kSocketRecvFrom[] = {
    {"SOCKET", "socket"}, {"void*", "buffer", D::None, true}, {"int", "length"},
    {"int", "flags"}, {"sockaddr*", "from", D::None, true, true},
    {"int*", "fromLength", D::None, true, true},
};
inline constexpr P kWsaSend[] = {
    {"SOCKET", "socket"}, {"LPWSABUF", "buffers"}, {"DWORD", "bufferCount"},
    {"LPDWORD", "bytesSent", D::None, true, true}, {"DWORD", "flags"},
    {"LPWSAOVERLAPPED", "overlapped", D::None, false, true},
    {"LPWSAOVERLAPPED_COMPLETION_ROUTINE", "completion", D::None, false, true},
};
inline constexpr P kWsaRecv[] = {
    {"SOCKET", "socket"}, {"LPWSABUF", "buffers", D::None, true},
    {"DWORD", "bufferCount"}, {"LPDWORD", "bytesReceived", D::None, true, true},
    {"LPDWORD", "flags", D::None, true},
    {"LPWSAOVERLAPPED", "overlapped", D::None, false, true},
    {"LPWSAOVERLAPPED_COMPLETION_ROUTINE", "completion", D::None, false, true},
};
inline constexpr P kWsaSendTo[] = {
    {"SOCKET", "socket"}, {"LPWSABUF", "buffers"}, {"DWORD", "bufferCount"},
    {"LPDWORD", "bytesSent", D::None, true, true}, {"DWORD", "flags"},
    {"const sockaddr*", "to", D::None, false, true}, {"int", "toLength"},
    {"LPWSAOVERLAPPED", "overlapped", D::None, false, true},
    {"LPWSAOVERLAPPED_COMPLETION_ROUTINE", "completion", D::None, false, true},
};
inline constexpr P kWsaRecvFrom[] = {
    {"SOCKET", "socket"}, {"LPWSABUF", "buffers", D::None, true},
    {"DWORD", "bufferCount"}, {"LPDWORD", "bytesReceived", D::None, true, true},
    {"LPDWORD", "flags", D::None, true},
    {"sockaddr*", "from", D::None, true, true},
    {"LPINT", "fromLength", D::None, true, true},
    {"LPWSAOVERLAPPED", "overlapped", D::None, false, true},
    {"LPWSAOVERLAPPED_COMPLETION_ROUTINE", "completion", D::None, false, true},
};
inline constexpr P kTransmitFile[] = {
    {"SOCKET", "socket"}, {"HANDLE", "file"}, {"DWORD", "bytesToWrite"},
    {"DWORD", "bytesPerSend"}, {"LPOVERLAPPED", "overlapped", D::None, false, true},
    {"LPTRANSMIT_FILE_BUFFERS", "transmitBuffers", D::None, false, true},
    {"DWORD", "flags"},
};
inline constexpr P kGetAddrInfo[] = {
    {"PCWSTR", "nodeName", D::None, false, true}, {"PCWSTR", "serviceName", D::None, false, true},
    {"const ADDRINFOW*", "hints", D::None, false, true},
    {"PADDRINFOW*", "result", D::None, true},
};
inline constexpr P kGetAddrInfoEx[] = {
    {"PCWSTR", "name", D::None, false, true},
    {"PCWSTR", "serviceName", D::None, false, true}, {"DWORD", "namespaceId"},
    {"LPGUID", "namespaceProvider", D::None, false, true},
    {"const ADDRINFOEXW*", "hints", D::None, false, true},
    {"PADDRINFOEXW*", "result", D::None, true},
    {"timeval*", "timeout", D::None, false, true},
    {"LPOVERLAPPED", "overlapped", D::None, false, true},
    {"LPLOOKUPSERVICE_COMPLETION_ROUTINE", "completion", D::None, false, true},
    {"LPHANDLE", "nameHandle", D::None, true, true},
};
inline constexpr P kGetHostByName[] = {{"const char*", "name"}};
inline constexpr P kGetHostByAddr[] = {
    {"const char*", "address"}, {"int", "addressLength"}, {"int", "addressType"},
};
inline constexpr P kGetNameInfo[] = {
    {"const sockaddr*", "address"}, {"socklen_t", "addressLength"},
    {"PSTR", "host", D::None, true, true}, {"DWORD", "hostLength"},
    {"PSTR", "service", D::None, true, true}, {"DWORD", "serviceLength"},
    {"int", "flags"},
};
inline constexpr P kDnsQuery[] = {
    {"PCTSTR", "name"}, {"WORD", "type"}, {"DWORD", "options"},
    {"PVOID", "extra", D::None, false, true},
    {"PDNS_RECORD*", "results", D::None, true},
    {"PVOID*", "reserved", D::None, true, true},
};
inline constexpr P kWinHttpOpen[] = {
    {"LPCWSTR", "userAgent"}, {"DWORD", "accessType"},
    {"LPCWSTR", "proxyName", D::None, false, true},
    {"LPCWSTR", "proxyBypass", D::None, false, true}, {"DWORD", "flags"},
};
inline constexpr P kWinHttpConnect[] = {
    {"HINTERNET", "session"}, {"LPCWSTR", "serverName"},
    {"INTERNET_PORT", "serverPort"}, {"DWORD", "reserved"},
};
inline constexpr P kWinHttpOpenRequest[] = {
    {"HINTERNET", "connect"}, {"LPCWSTR", "verb", D::None, false, true},
    {"LPCWSTR", "objectName", D::None, false, true},
    {"LPCWSTR", "version", D::None, false, true},
    {"LPCWSTR", "referrer", D::None, false, true},
    {"LPCWSTR*", "acceptTypes", D::None, false, true}, {"DWORD", "flags"},
};
inline constexpr P kWinHttpSendRequest[] = {
    {"HINTERNET", "request"}, {"LPCWSTR", "headers", D::None, false, true},
    {"DWORD", "headersLength"}, {"LPVOID", "optionalData", D::None, false, true},
    {"DWORD", "optionalLength"}, {"DWORD", "totalLength"}, {"DWORD_PTR", "context"},
};
inline constexpr P kWinHttpGetProxyForUrl[] = {
    {"HINTERNET", "session"}, {"LPCWSTR", "url"},
    {"WINHTTP_AUTOPROXY_OPTIONS*", "autoProxyOptions"},
    {"WINHTTP_PROXY_INFO*", "proxyInfo", D::None, true},
};
inline constexpr P kAddRequestHeaders[] = {
    {"HINTERNET", "request"}, {"LPCTSTR", "headers"},
    {"DWORD", "headersLength"}, {"DWORD", "modifiers"},
};
inline constexpr P kWinHttpSetCredentials[] = {
    {"HINTERNET", "request"}, {"DWORD", "authTargets"}, {"DWORD", "authScheme"},
    {"LPCWSTR", "userName", D::None, false, true},
    {"LPCWSTR", "password", D::None, false, true},
    {"LPVOID", "authParams", D::None, false, true},
};
inline constexpr P kInternetOpen[] = {
    {"LPCTSTR", "agent"}, {"DWORD", "accessType"},
    {"LPCTSTR", "proxy", D::None, false, true},
    {"LPCTSTR", "proxyBypass", D::None, false, true}, {"DWORD", "flags"},
};
inline constexpr P kInternetConnect[] = {
    {"HINTERNET", "internet"}, {"LPCTSTR", "serverName"},
    {"INTERNET_PORT", "serverPort"}, {"LPCTSTR", "userName", D::None, false, true},
    {"LPCTSTR", "password", D::None, false, true}, {"DWORD", "service"},
    {"DWORD", "flags"}, {"DWORD_PTR", "context"},
};
inline constexpr P kHttpOpenRequest[] = {
    {"HINTERNET", "connect"}, {"LPCTSTR", "verb", D::None, false, true},
    {"LPCTSTR", "objectName", D::None, false, true},
    {"LPCTSTR", "version", D::None, false, true},
    {"LPCTSTR", "referrer", D::None, false, true},
    {"LPCTSTR*", "acceptTypes", D::None, false, true}, {"DWORD", "flags"},
    {"DWORD_PTR", "context"},
};
inline constexpr P kHttpSendRequest[] = {
    {"HINTERNET", "request"}, {"LPCTSTR", "headers", D::None, false, true},
    {"DWORD", "headersLength"}, {"LPVOID", "optionalData", D::None, false, true},
    {"DWORD", "optionalLength"},
};
inline constexpr P kInternetOpenUrl[] = {
    {"HINTERNET", "internet"}, {"LPCTSTR", "url"},
    {"LPCTSTR", "headers", D::None, false, true}, {"DWORD", "headersLength"},
    {"DWORD", "flags"}, {"DWORD_PTR", "context"},
};
inline constexpr P kHttpSendRequestEx[] = {
    {"HINTERNET", "request"},
    {"LPINTERNET_BUFFERS", "buffersIn", D::None, false, true},
    {"LPINTERNET_BUFFERS", "buffersOut", D::None, true, true},
    {"DWORD", "flags"}, {"DWORD_PTR", "context"},
};
inline constexpr P kHttpEndRequest[] = {
    {"HINTERNET", "request"},
    {"LPINTERNET_BUFFERS", "buffersOut", D::None, true, true},
    {"DWORD", "flags"}, {"DWORD_PTR", "context"},
};
inline constexpr P kInternetReadFileEx[] = {
    {"HINTERNET", "file"}, {"LPINTERNET_BUFFERS", "buffersOut", D::None, true},
    {"DWORD", "flags"}, {"DWORD_PTR", "context"},
};
inline constexpr P kInternetReadWrite[] = {
    {"HINTERNET", "handle"}, {"LPVOID", "buffer"}, {"DWORD", "bytesRequested"},
    {"LPDWORD", "bytesTransferred", D::None, true},
};
inline constexpr P kHttpQueryInfo[] = {
    {"HINTERNET", "request"}, {"DWORD", "infoLevel"}, {"LPVOID", "buffer", D::None, true},
    {"LPDWORD", "bufferLength", D::None, true}, {"LPDWORD", "index", D::None, true, true},
};
inline constexpr P kWinHttpReadWrite[] = {
    {"HINTERNET", "request"}, {"LPVOID", "buffer"}, {"DWORD", "bytesRequested"},
    {"LPDWORD", "bytesTransferred", D::None, true},
};
inline constexpr P kWinHttpQueryHeaders[] = {
    {"HINTERNET", "request"}, {"DWORD", "infoLevel"},
    {"LPCWSTR", "name", D::None, false, true}, {"LPVOID", "buffer", D::None, true},
    {"LPDWORD", "bufferLength", D::None, true}, {"LPDWORD", "index", D::None, true, true},
};
inline constexpr P kOneInternetHandle[] = {{"HINTERNET", "handle"}};
inline constexpr P kUrlDownloadToFile[] = {
    {"LPUNKNOWN", "caller", D::None, false, true}, {"LPCTSTR", "url"},
    {"LPCTSTR", "fileName"}, {"DWORD", "reserved"},
    {"LPBINDSTATUSCALLBACK", "callback", D::None, false, true},
};
inline constexpr P kUrlDownloadToCacheFile[] = {
    {"LPUNKNOWN", "caller", D::None, false, true}, {"LPCTSTR", "url"},
    {"LPTSTR", "fileName", D::None, true}, {"DWORD", "fileNameCapacity"},
    {"DWORD", "reserved"},
    {"LPBINDSTATUSCALLBACK", "callback", D::None, false, true},
};
inline constexpr P kUrlOpenStream[] = {
    {"LPUNKNOWN", "caller", D::None, false, true}, {"LPCTSTR", "url"},
    {"DWORD", "reserved"},
    {"LPBINDSTATUSCALLBACK", "callback", D::None, false, true},
};
inline constexpr P kUrlOpenBlockingStream[] = {
    {"LPUNKNOWN", "caller", D::None, false, true}, {"LPCTSTR", "url"},
    {"LPSTREAM*", "stream", D::None, true}, {"DWORD", "reserved"},
    {"LPBINDSTATUSCALLBACK", "callback", D::None, false, true},
};
inline constexpr P kMessageBox[] = {
    {"HWND", "owner", D::None, false, true}, {"LPCWSTR", "text"},
    {"LPCWSTR", "caption", D::None, false, true}, {"UINT", "type", D::MessageBoxFlags},
};
inline constexpr P kWaitForSingleObject[] = {
    {"HANDLE", "handle"}, {"DWORD", "milliseconds", D::WaitMilliseconds},
};
inline constexpr P kHeapAlloc[] = {
    {"HANDLE", "heap"}, {"DWORD", "flags"}, {"SIZE_T", "bytes"},
};
inline constexpr P kOneString[] = {{"LPCWSTR", "name"}};
inline constexpr P kGetProcAddress[] = {{"HMODULE", "module"}, {"LPCSTR", "procedureName"}};
inline constexpr P kExitProcess[] = {{"UINT", "exitCode"}};
inline constexpr P kSleep[] = {{"DWORD", "milliseconds", D::WaitMilliseconds}};

inline constexpr ApiPrototypeInfo kPrototypes[] = {
    {"createfile", "HANDLE", kCreateFile, 7},
    {"readfile", "BOOL", kReadWriteFile, 5},
    {"writefile", "BOOL", kReadWriteFile, 5},
    {"virtualalloc", "LPVOID", kVirtualAlloc, 4},
    {"virtualallocex", "LPVOID", kVirtualAllocEx, 5},
    {"virtualprotect", "BOOL", kVirtualProtect, 4},
    {"virtualprotectex", "BOOL", kVirtualProtectEx, 5},
    {"openprocess", "HANDLE", kOpenProcess, 3},
    {"openthread", "HANDLE", kOpenThread, 3},
    {"createremotethread", "HANDLE", kCreateRemoteThread, 7},
    {"createprocess", "BOOL", kCreateProcess, 10},
    {"readprocessmemory", "BOOL", kProcessMemory, 5},
    {"writeprocessmemory", "BOOL", kProcessMemory, 5},
    {"regopenkeyex", "LSTATUS", kRegOpenKeyEx, 5},
    {"regcreatekeyex", "LSTATUS", kRegCreateKeyEx, 9},
    {"regsetvalueex", "LSTATUS", kRegSetValueEx, 6},
    {"socket", "SOCKET", kSocket, 3},
    {"wsasocket", "SOCKET", kWsaSocket, 6},
    {"accept", "SOCKET", kAccept, 3},
    {"acceptex", "BOOL", kAcceptEx, 8},
    {"connect", "int", kConnect, 3},
    {"connectex", "BOOL", kConnectEx, 7},
    {"wsaconnect", "int", kWsaConnect, 7},
    {"wsastartup", "int", kWsaStartup, 2},
    {"wsacleanup", "int", nullptr, 0},
    {"closesocket", "int", kOneSocket, 1},
    {"send", "int", kSocketBuffer, 4},
    {"recv", "int", kSocketBuffer, 4},
    {"sendto", "int", kSocketSendTo, 6},
    {"recvfrom", "int", kSocketRecvFrom, 6},
    {"transmitfile", "BOOL", kTransmitFile, 7},
    {"wsasend", "int", kWsaSend, 7},
    {"wsarecv", "int", kWsaRecv, 7},
    {"wsasendto", "int", kWsaSendTo, 9},
    {"wsarecvfrom", "int", kWsaRecvFrom, 9},
    {"getaddrinfo", "INT", kGetAddrInfo, 4},
    {"getaddrinfoex", "INT", kGetAddrInfoEx, 10},
    {"gethostbyname", "hostent*", kGetHostByName, 1},
    {"gethostbyaddr", "hostent*", kGetHostByAddr, 3},
    {"getnameinfo", "INT", kGetNameInfo, 7},
    {"dnsquery", "DNS_STATUS", kDnsQuery, 6},
    {"winhttpgetproxyforurl", "BOOL", kWinHttpGetProxyForUrl, 4},
    {"winhttpopen", "HINTERNET", kWinHttpOpen, 5},
    {"winhttpconnect", "HINTERNET", kWinHttpConnect, 4},
    {"winhttpopenrequest", "HINTERNET", kWinHttpOpenRequest, 7},
    {"winhttpaddrequestheaders", "BOOL", kAddRequestHeaders, 4},
    {"winhttpsetcredentials", "BOOL", kWinHttpSetCredentials, 6},
    {"winhttpsendrequest", "BOOL", kWinHttpSendRequest, 7},
    {"winhttpwritedata", "BOOL", kWinHttpReadWrite, 4},
    {"winhttpreceiveresponse", "BOOL", kOneInternetHandle, 1},
    {"winhttpreaddata", "BOOL", kWinHttpReadWrite, 4},
    {"winhttpqueryheaders", "BOOL", kWinHttpQueryHeaders, 6},
    {"winhttpclosehandle", "BOOL", kOneInternetHandle, 1},
    {"internetopen", "HINTERNET", kInternetOpen, 5},
    {"internetconnect", "HINTERNET", kInternetConnect, 8},
    {"httpopenrequest", "HINTERNET", kHttpOpenRequest, 8},
    {"internetopenurl", "HINTERNET", kInternetOpenUrl, 6},
    {"httpaddrequestheaders", "BOOL", kAddRequestHeaders, 4},
    {"httpsendrequest", "BOOL", kHttpSendRequest, 5},
    {"httpsendrequestex", "BOOL", kHttpSendRequestEx, 5},
    {"httpendrequest", "BOOL", kHttpEndRequest, 4},
    {"internetreadfile", "BOOL", kInternetReadWrite, 4},
    {"internetreadfileex", "BOOL", kInternetReadFileEx, 4},
    {"internetwritefile", "BOOL", kInternetReadWrite, 4},
    {"httpqueryinfo", "BOOL", kHttpQueryInfo, 5},
    {"internetclosehandle", "BOOL", kOneInternetHandle, 1},
    {"urldownloadtofile", "HRESULT", kUrlDownloadToFile, 5},
    {"urldownloadtocachefile", "HRESULT", kUrlDownloadToCacheFile, 6},
    {"urlopenstream", "HRESULT", kUrlOpenStream, 4},
    {"urlopenpullstream", "HRESULT", kUrlOpenStream, 4},
    {"urlopenblockingstream", "HRESULT", kUrlOpenBlockingStream, 5},
    {"messagebox", "int", kMessageBox, 4},
    {"waitforsingleobject", "DWORD", kWaitForSingleObject, 2},
    {"heapalloc", "LPVOID", kHeapAlloc, 3},
    {"loadlibrary", "HMODULE", kOneString, 1},
    {"getmodulehandle", "HMODULE", kOneString, 1},
    {"getprocaddress", "FARPROC", kGetProcAddress, 2},
    {"exitprocess", "void", kExitProcess, 1, true},
    {"sleep", "void", kSleep, 1},
};

struct NamedValue { uint64_t value; std::string_view name; };

inline void appendPart(std::string& out, std::string_view part) {
    if (!out.empty()) out += " | ";
    out.append(part.data(), part.size());
}

inline std::string hexValue(uint64_t value) {
    char buffer[24]{};
    std::snprintf(buffer, sizeof(buffer), "0x%llX",
                  static_cast<unsigned long long>(value));
    return buffer;
}

template <size_t N>
inline std::string exactValue(uint64_t value, const NamedValue (&values)[N]) {
    for (const NamedValue& item : values)
        if (item.value == value) return std::string(item.name);
    return {};
}

template <size_t N>
inline std::string flagValue(uint64_t value, const NamedValue (&values)[N]) {
    if (!value) return "0";
    // Prefer an exact aggregate spelling (for example PROCESS_ALL_ACCESS).
    for (const NamedValue& item : values)
        if (item.value && item.value == value) return std::string(item.name);
    uint64_t remaining = value;
    std::string out;
    for (const NamedValue& item : values) {
        if (!item.value || (remaining & item.value) != item.value) continue;
        appendPart(out, item.name);
        remaining &= ~item.value;
    }
    if (remaining) appendPart(out, hexValue(remaining));
    return out;
}

} // namespace api_database_detail

inline std::string NormalizeApiDatabaseName(std::string_view name) {
    const size_t bang = name.find_last_of("!.");
    if (bang != std::string_view::npos) name.remove_prefix(bang + 1);
    while (!name.empty() && (name.front() == '_' || name.front() == '@'))
        name.remove_prefix(1);
    std::string normalized;
    normalized.reserve(name.size());
    for (unsigned char c : name) normalized.push_back(static_cast<char>(std::tolower(c)));

    // stdcall decoration: Function@20. Do not strip an interior @ from a C++ name.
    const size_t at = normalized.find_last_of('@');
    if (at != std::string::npos && at + 1 < normalized.size()) {
        bool digits = true;
        for (size_t i = at + 1; i < normalized.size(); ++i)
            digits = digits && std::isdigit(static_cast<unsigned char>(normalized[i]));
        if (digits) normalized.resize(at);
    }
    // The selected APIs use conventional A/W/UTF8 ABI suffixes.  Handle the
    // DNS underscore spellings before the ordinary final-letter form.
    for (std::string_view suffix : { std::string_view("_utf8"),
                                     std::string_view("_a"),
                                     std::string_view("_w") }) {
        if (normalized.size() > suffix.size() && normalized.ends_with(suffix)) {
            normalized.resize(normalized.size() - suffix.size());
            return normalized;
        }
    }
    if (normalized.size() > 1 &&
        (normalized.back() == 'a' || normalized.back() == 'w'))
        normalized.pop_back();
    return normalized;
}

inline const ApiPrototypeInfo* FindWindowsApiPrototype(std::string_view name) {
    const std::string normalized = NormalizeApiDatabaseName(name);
    for (const ApiPrototypeInfo& prototype : api_database_detail::kPrototypes)
        if (prototype.canonicalName == normalized) return &prototype;
    for (const ApiPrototypeInfo& prototype : api_database_detail::kPrototypes) {
        // A bounded set of canonical base names intentionally covers common
        // Ex/ExW variants without proliferating duplicate records.
        if (normalized.size() == prototype.canonicalName.size() + 2 &&
            normalized.compare(0, prototype.canonicalName.size(), prototype.canonicalName) == 0 &&
            normalized.ends_with("ex"))
            return &prototype;
    }
    return nullptr;
}

// Shared, exact noreturn contract for discovery, CFG construction, annotations,
// and export. Normalize decorations/module qualifiers once, then compare whole
// API names so innocuous functions such as GetExitCodeProcess cannot match.
inline bool IsKnownNoreturnApi(std::string_view name) {
    if (const ApiPrototypeInfo* prototype = FindWindowsApiPrototype(name);
        prototype && prototype->noreturn)
        return true;
    const std::string normalized = NormalizeApiDatabaseName(name);
    static constexpr std::string_view kRuntimeSet[] = {
        "exitprocess", "rtlexituserprocess", "exit", "o_exit",
        "quick_exit", "abort", "fastfail",
        "invalid_parameter_noinfo_noreturn",
    };
    for (std::string_view candidate : kRuntimeSet)
        if (normalized == candidate) return true;
    return false;
}

inline std::string FormatApiConstant(ApiValueDomain domain, uint64_t value) {
    using namespace api_database_detail;
    static constexpr NamedValue kGenericAccess[] = {
        {0x80000000ull, "GENERIC_READ"}, {0x40000000ull, "GENERIC_WRITE"},
        {0x20000000ull, "GENERIC_EXECUTE"}, {0x10000000ull, "GENERIC_ALL"},
        {0x00010000ull, "DELETE"}, {0x00020000ull, "READ_CONTROL"},
        {0x00040000ull, "WRITE_DAC"}, {0x00080000ull, "WRITE_OWNER"},
        {0x00100000ull, "SYNCHRONIZE"},
    };
    static constexpr NamedValue kFileShare[] = {
        {0x1, "FILE_SHARE_READ"}, {0x2, "FILE_SHARE_WRITE"}, {0x4, "FILE_SHARE_DELETE"},
    };
    static constexpr NamedValue kCreation[] = {
        {1, "CREATE_NEW"}, {2, "CREATE_ALWAYS"}, {3, "OPEN_EXISTING"},
        {4, "OPEN_ALWAYS"}, {5, "TRUNCATE_EXISTING"},
    };
    static constexpr NamedValue kFileAttributes[] = {
        {0x00000001, "FILE_ATTRIBUTE_READONLY"}, {0x00000002, "FILE_ATTRIBUTE_HIDDEN"},
        {0x00000004, "FILE_ATTRIBUTE_SYSTEM"}, {0x00000020, "FILE_ATTRIBUTE_ARCHIVE"},
        {0x00000080, "FILE_ATTRIBUTE_NORMAL"}, {0x00000100, "FILE_ATTRIBUTE_TEMPORARY"},
        {0x00000200, "FILE_ATTRIBUTE_SPARSE_FILE"}, {0x00000400, "FILE_ATTRIBUTE_REPARSE_POINT"},
        {0x01000000, "FILE_FLAG_BACKUP_SEMANTICS"}, {0x02000000, "FILE_FLAG_POSIX_SEMANTICS"},
        {0x04000000, "FILE_FLAG_DELETE_ON_CLOSE"}, {0x08000000, "FILE_FLAG_SEQUENTIAL_SCAN"},
        {0x10000000, "FILE_FLAG_RANDOM_ACCESS"}, {0x20000000, "FILE_FLAG_NO_BUFFERING"},
        {0x40000000, "FILE_FLAG_OVERLAPPED"}, {0x80000000, "FILE_FLAG_WRITE_THROUGH"},
    };
    static constexpr NamedValue kProtectionBase[] = {
        {0x01, "PAGE_NOACCESS"}, {0x02, "PAGE_READONLY"}, {0x04, "PAGE_READWRITE"},
        {0x08, "PAGE_WRITECOPY"}, {0x10, "PAGE_EXECUTE"}, {0x20, "PAGE_EXECUTE_READ"},
        {0x40, "PAGE_EXECUTE_READWRITE"}, {0x80, "PAGE_EXECUTE_WRITECOPY"},
    };
    static constexpr NamedValue kProtectionMods[] = {
        {0x100, "PAGE_GUARD"}, {0x200, "PAGE_NOCACHE"}, {0x400, "PAGE_WRITECOMBINE"},
    };
    static constexpr NamedValue kAllocation[] = {
        {0x00001000, "MEM_COMMIT"}, {0x00002000, "MEM_RESERVE"}, {0x00080000, "MEM_RESET"},
        {0x00100000, "MEM_TOP_DOWN"}, {0x00200000, "MEM_WRITE_WATCH"},
        {0x00400000, "MEM_PHYSICAL"}, {0x01000000, "MEM_RESET_UNDO"},
        {0x20000000, "MEM_LARGE_PAGES"},
    };
    static constexpr NamedValue kProcessAccess[] = {
        {0x001F0FFF, "PROCESS_ALL_ACCESS"}, {0x0001, "PROCESS_TERMINATE"},
        {0x0002, "PROCESS_CREATE_THREAD"}, {0x0008, "PROCESS_VM_OPERATION"},
        {0x0010, "PROCESS_VM_READ"}, {0x0020, "PROCESS_VM_WRITE"},
        {0x0040, "PROCESS_DUP_HANDLE"}, {0x0080, "PROCESS_CREATE_PROCESS"},
        {0x0100, "PROCESS_SET_QUOTA"}, {0x0200, "PROCESS_SET_INFORMATION"},
        {0x0400, "PROCESS_QUERY_INFORMATION"}, {0x0800, "PROCESS_SUSPEND_RESUME"},
        {0x1000, "PROCESS_QUERY_LIMITED_INFORMATION"}, {0x00100000, "SYNCHRONIZE"},
    };
    static constexpr NamedValue kThreadAccess[] = {
        {0x001F03FF, "THREAD_ALL_ACCESS"}, {0x0001, "THREAD_TERMINATE"},
        {0x0002, "THREAD_SUSPEND_RESUME"}, {0x0008, "THREAD_GET_CONTEXT"},
        {0x0010, "THREAD_SET_CONTEXT"}, {0x0020, "THREAD_SET_INFORMATION"},
        {0x0040, "THREAD_QUERY_INFORMATION"}, {0x0080, "THREAD_SET_THREAD_TOKEN"},
        {0x0100, "THREAD_IMPERSONATE"}, {0x0200, "THREAD_DIRECT_IMPERSONATION"},
        {0x0800, "THREAD_QUERY_LIMITED_INFORMATION"}, {0x00100000, "SYNCHRONIZE"},
    };
    static constexpr NamedValue kRegistryAccess[] = {
        {0x0001, "KEY_QUERY_VALUE"}, {0x0002, "KEY_SET_VALUE"},
        {0x0004, "KEY_CREATE_SUB_KEY"}, {0x0008, "KEY_ENUMERATE_SUB_KEYS"},
        {0x0010, "KEY_NOTIFY"}, {0x0020, "KEY_CREATE_LINK"},
        {0x0100, "KEY_WOW64_64KEY"}, {0x0200, "KEY_WOW64_32KEY"},
        {0x00020019, "KEY_READ"}, {0x00020006, "KEY_WRITE"},
        {0x000F003F, "KEY_ALL_ACCESS"},
    };
    static constexpr NamedValue kSocketFamily[] = {
        {0, "AF_UNSPEC"}, {1, "AF_UNIX"}, {2, "AF_INET"}, {23, "AF_INET6"},
    };
    static constexpr NamedValue kSocketType[] = {
        {1, "SOCK_STREAM"}, {2, "SOCK_DGRAM"}, {3, "SOCK_RAW"},
        {4, "SOCK_RDM"}, {5, "SOCK_SEQPACKET"},
    };
    static constexpr NamedValue kSocketProtocol[] = {
        {0, "IPPROTO_IP"}, {1, "IPPROTO_ICMP"}, {6, "IPPROTO_TCP"},
        {17, "IPPROTO_UDP"}, {41, "IPPROTO_IPV6"}, {58, "IPPROTO_ICMPV6"},
    };
    static constexpr NamedValue kMessageBox[] = {
        {0x00000001, "MB_OKCANCEL"}, {0x00000002, "MB_ABORTRETRYIGNORE"},
        {0x00000003, "MB_YESNOCANCEL"}, {0x00000004, "MB_YESNO"},
        {0x00000005, "MB_RETRYCANCEL"}, {0x00000006, "MB_CANCELTRYCONTINUE"},
        {0x00000010, "MB_ICONERROR"}, {0x00000020, "MB_ICONQUESTION"},
        {0x00000030, "MB_ICONWARNING"}, {0x00000040, "MB_ICONINFORMATION"},
        {0x00000100, "MB_DEFBUTTON2"}, {0x00000200, "MB_DEFBUTTON3"},
        {0x00000300, "MB_DEFBUTTON4"}, {0x00001000, "MB_SYSTEMMODAL"},
        {0x00040000, "MB_TOPMOST"}, {0x00080000, "MB_RIGHT"},
    };

    switch (domain) {
        case ApiValueDomain::None: return {};
        case ApiValueDomain::Boolean:
            return value == 0 ? "FALSE" : value == 1 ? "TRUE" : hexValue(value);
        case ApiValueDomain::GenericAccess: return flagValue(value, kGenericAccess);
        case ApiValueDomain::FileShare: return flagValue(value, kFileShare);
        case ApiValueDomain::CreationDisposition: {
            std::string out = exactValue(value, kCreation); return out.empty() ? hexValue(value) : out;
        }
        case ApiValueDomain::FileAttributes: return flagValue(value, kFileAttributes);
        case ApiValueDomain::PageProtection: {
            const uint64_t base = value & 0xFFu;
            std::string out = exactValue(base, kProtectionBase);
            if (out.empty() && base) out = hexValue(base);
            const uint64_t modifiers = value & ~uint64_t{0xFF};
            if (modifiers) {
                std::string mods = flagValue(modifiers, kProtectionMods);
                if (!mods.empty()) appendPart(out, mods);
            }
            return out.empty() ? "0" : out;
        }
        case ApiValueDomain::AllocationType: return flagValue(value, kAllocation);
        case ApiValueDomain::ProcessAccess: return flagValue(value, kProcessAccess);
        case ApiValueDomain::ThreadAccess: return flagValue(value, kThreadAccess);
        case ApiValueDomain::RegistryAccess: return flagValue(value, kRegistryAccess);
        case ApiValueDomain::SocketFamily: {
            std::string out = exactValue(value, kSocketFamily); return out.empty() ? hexValue(value) : out;
        }
        case ApiValueDomain::SocketType: {
            std::string out = exactValue(value, kSocketType); return out.empty() ? hexValue(value) : out;
        }
        case ApiValueDomain::SocketProtocol: {
            std::string out = exactValue(value, kSocketProtocol); return out.empty() ? hexValue(value) : out;
        }
        case ApiValueDomain::MessageBoxFlags: {
            if (!value) return "MB_OK";
            // The low nibble is an enum; the remaining bits are flags.
            const uint64_t buttons = value & 0xFu;
            std::string out = buttons ? exactValue(buttons, kMessageBox) : "MB_OK";
            uint64_t remaining = value & ~uint64_t{0xF};
            for (const NamedValue& item : kMessageBox) {
                if (item.value < 0x10 || !item.value || (remaining & item.value) != item.value) continue;
                appendPart(out, item.name);
                remaining &= ~item.value;
            }
            if (remaining) appendPart(out, hexValue(remaining));
            return out;
        }
        case ApiValueDomain::WaitMilliseconds:
            return value == 0xFFFFFFFFull ? "INFINITE" : std::string();
    }
    return {};
}

inline std::string FormatWindowsApiArgument(std::string_view apiName, size_t index,
                                            uint64_t value) {
    const ApiPrototypeInfo* prototype = FindWindowsApiPrototype(apiName);
    if (!prototype || index >= prototype->parameterCount) return {};
    const ApiParameterInfo& parameter = prototype->parameters[index];
    std::string out(parameter.name);
    const std::string symbolic = FormatApiConstant(parameter.valueDomain, value);
    out += '=';
    out += symbolic.empty() ? api_database_detail::hexValue(value) : symbolic;
    return out;
}

inline std::string FormatWindowsApiPrototype(std::string_view apiName) {
    const ApiPrototypeInfo* prototype = FindWindowsApiPrototype(apiName);
    if (!prototype) return {};
    std::string out(prototype->returnType);
    out += ' ';
    out.append(prototype->canonicalName.data(), prototype->canonicalName.size());
    out += '(';
    for (uint8_t i = 0; i < prototype->parameterCount; ++i) {
        if (i) out += ", ";
        const ApiParameterInfo& parameter = prototype->parameters[i];
        out.append(parameter.type.data(), parameter.type.size());
        out += ' ';
        out.append(parameter.name.data(), parameter.name.size());
        if (parameter.optional) out += "?";
    }
    out += ')';
    return out;
}

} // namespace ds
