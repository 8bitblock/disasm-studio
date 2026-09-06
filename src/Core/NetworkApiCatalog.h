#pragma once
//
// NetworkApiCatalog.h
// Exact, DLL-aware classification of the Windows networking APIs used by the
// offline crackme triage pass.  This deliberately does not use substring
// matching: a user-interface import such as SendMessageW is not socket send().
//


#include <cstdint>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

enum class NetworkApiFamily : uint8_t {
    Winsock = 0,
    DnsApi,
    WinHttp,
    WinInet,
    UrlMon,
};

// The five observable stages used by static and (later) live network trails.
// "Connect" also contains library/session creation APIs; it means transport
// setup, not proof that a remote connection was completed.
enum class NetworkStage : uint8_t {
    Resolve = 0,
    Connect,
    Request,
    Write,
    Read,
    Count,
};

using NetworkStageMask = uint8_t;

constexpr NetworkStageMask NetworkStageBit(NetworkStage stage) {
    return stage < NetworkStage::Count
         ? static_cast<NetworkStageMask>(1u << static_cast<unsigned>(stage))
         : 0;
}

const char* NetworkApiFamilyText(NetworkApiFamily family);
const char* NetworkStageText(NetworkStage stage);

struct NetworkApiMatch {
    NetworkApiFamily family = NetworkApiFamily::Winsock;
    NetworkStage     stage = NetworkStage::Connect;
    std::string      dll;             // normalized lower-case module, no .dll
    std::string      canonicalName;   // stable catalog spelling, no A/W suffix
    std::string      normalizedName;  // decoration-free lower-case lookup key
    bool             lifecycle = false; // cleanup/close evidence; no trail stage
};

// Machine-readable return contracts are kept beside the exact API catalog so
// static analysis and live observation agree on what a raw return value means.
// These rules describe the immediate function return.  A false/SOCKET_ERROR
// return accompanied by an asynchronous-pending error is disclosed separately
// through asyncPendingPossible; it must not be relabelled as completed success.
enum class NetworkReturnKind : uint8_t {
    Bool = 0,          // Win32 BOOL
    IntStatus,        // int/LONG status code
    SignedByteCount,  // int byte count; zero can be a valid result
    SocketHandle,     // pointer-width SOCKET
    InternetHandle,   // HINTERNET
    Pointer,          // hostent* or another API-owned pointer
    HResult,
};

enum class NetworkReturnSuccessRule : uint8_t {
    NonZero = 0,
    Zero,
    NonNegative,
    NotInvalidSocket,
    NonNull,
    HResultSucceeded,
};

enum class NetworkFailureSentinel : uint8_t {
    Zero = 0,          // FALSE
    Null,              // NULL handle/pointer
    SocketError,       // SOCKET_ERROR (-1 as a signed int)
    InvalidSocket,     // INVALID_SOCKET (all pointer-width bits set)
    NonZeroStatus,
    FailedHResult,
};

enum class NetworkOutParameterRole : uint8_t {
    AddressList = 0,
    SessionData,
    HostEntry,
    HostText,
    ServiceText,
    SocketAddress,
    SocketAddressLength,
    ByteCount,
    PayloadBuffer,
    Flags,
    ProxyInfo,
    HeaderBuffer,
    BufferSize,
    QueryIndex,
    DnsRecordList,
    CacheFilePath,
    ComStream,
    AsyncOperationHandle,
};

enum class NetworkOutParameterValidity : uint8_t {
    OnSuccess = 0,
    OnSuccessOrAsyncCompletion,
    OnSuccessOrRequiredSize,
    OnAsyncPending,
};

enum class NetworkZeroResultMeaning : uint8_t {
    None = 0,
    EndOfStreamOrEmptyMessage,
    EndOfBody,
};

enum class NetworkAsyncPendingRule : uint8_t {
    None = 0,
    LastErrorIoPending,          // GetLastError/WSAGetLastError == 997
    LastErrorNonblockingConnect, // WSAEWOULDBLOCK/INPROGRESS/ALREADY
    DirectStatusIoPending,       // return value itself is WSA_IO_PENDING
};

struct NetworkApiOutParameter {
    uint8_t argumentIndex = 0; // zero-based; aligns with ApiArgumentObservation
    NetworkOutParameterRole role = NetworkOutParameterRole::ByteCount;
    NetworkOutParameterValidity validity = NetworkOutParameterValidity::OnSuccess;
    bool inOut = false;
    std::string_view meaning;

    constexpr uint8_t oneBasedOrdinal() const {
        return static_cast<uint8_t>(argumentIndex + 1);
    }
};

constexpr std::size_t kMaxNetworkContractOutParameters = 5;

struct NetworkApiReturnContract {
    NetworkReturnKind returnKind = NetworkReturnKind::Bool;
    NetworkReturnSuccessRule successRule = NetworkReturnSuccessRule::NonZero;
    NetworkFailureSentinel failureSentinel = NetworkFailureSentinel::Zero;
    std::string_view returnType;      // documented SDK spelling
    std::string_view successMeaning;  // concise analyst-facing interpretation
    std::string_view failureMeaning;  // sentinel/status interpretation
    std::array<NetworkApiOutParameter, kMaxNetworkContractOutParameters> outParameters{};
    uint8_t outParameterCount = 0;
    NetworkZeroResultMeaning zeroResultMeaning = NetworkZeroResultMeaning::None;
    bool asyncPendingPossible = false;
    NetworkAsyncPendingRule pendingRule = NetworkAsyncPendingRule::None;
    bool closesResourceOnSuccess = false;
};

const char* NetworkReturnKindText(NetworkReturnKind kind);
const char* NetworkReturnSuccessRuleText(NetworkReturnSuccessRule rule);
const char* NetworkFailureSentinelText(NetworkFailureSentinel sentinel);
const char* NetworkOutParameterRoleText(NetworkOutParameterRole role);
const char* NetworkOutParameterValidityText(NetworkOutParameterValidity validity);
const char* NetworkZeroResultMeaningText(NetworkZeroResultMeaning meaning);
const char* NetworkAsyncPendingRuleText(NetworkAsyncPendingRule rule);

enum class NetworkReturnDisposition : uint8_t {
    Success = 0,
    Failure,
    Indeterminate, // a pending-capable failure return without decisive error state
};

const char* NetworkReturnDispositionText(NetworkReturnDisposition disposition);

// Exact DLL + symbol lookup for the documented return/out-parameter contract.
// Unknown APIs never receive a family-level guess.
std::optional<NetworkApiReturnContract>
LookupNetworkApiReturnContract(std::string_view dll, std::string_view symbol);

// Interpret a captured immediate return using the contract's ABI width.  BOOL,
// int, status and HRESULT values use their documented low 32 bits; SOCKET uses
// pointerWidthBits (32 for WOW64, 64 for native x64).
bool NetworkReturnIsImmediateSuccess(const NetworkApiReturnContract& contract,
                                     uint64_t rawValue,
                                     uint8_t pointerWidthBits = 64);

// Tri-state interpretation for live observations.  errorCode is the captured
// GetLastError/WSAGetLastError value when available.  Pending-capable APIs stay
// indeterminate when their sentinel is observed without decisive error state;
// an explicit ERROR_IO_PENDING/WSA_IO_PENDING/nonblocking-connect status also
// stays indeterminate until the completion is observed.
NetworkReturnDisposition InterpretNetworkApiReturn(
    const NetworkApiReturnContract& contract,
    uint64_t rawValue,
    std::optional<uint32_t> errorCode = std::nullopt,
    uint8_t pointerWidthBits = 64);

// Keep only the basename, lower-case it, and remove a trailing ".dll".  Import
// libraries and absolute loader paths therefore share one module identity.
std::string NormalizeNetworkDll(std::string_view dll);

// Remove common import/IAT decorations (`__imp_`, a leading `_`, stdcall `@N`)
// and lower-case the symbol.  An A/W suffix is removed only when the remaining
// name is an exact catalog entry, so arbitrary functions are never truncated.
std::string NormalizeNetworkApiName(std::string_view symbol);

// Exact module + symbol lookup.  Unknown/empty/wrong DLL names do not fall back
// to name-only matching.  This is what prevents SendMessageW and similarly named
// non-network functions from becoming network evidence.
std::optional<NetworkApiMatch> LookupNetworkApi(std::string_view dll,
                                                std::string_view symbol);

// Stable catalog enumeration used by live-probe coverage reporting. Callers
// can therefore disclose every statically known row that lacks a safe ABI
// decoder instead of silently presenting partial coverage as complete.
std::vector<NetworkApiMatch> EnumerateNetworkApis();

} // namespace ds
