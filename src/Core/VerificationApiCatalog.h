#pragma once
//
// VerificationApiCatalog.h
// Exact DLL+symbol contracts for APIs whose documented result can report a
// cryptographic signature/trust decision.  Merely importing one of these APIs
// is evidence of capability, never proof that a particular entitlement was
// verified.  Callers must separately prove result provenance into an
// authorization branch before publishing a verification stage.
//

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

inline constexpr size_t kVerificationLookupFieldMaxBytes = 1024;
inline constexpr size_t kVerificationNormalizedDllMaxBytes = 128;
inline constexpr size_t kVerificationNormalizedSymbolMaxBytes = 256;
inline constexpr size_t kVerificationApiCatalogHardMaxRows = 64;

enum class VerificationApiFamily : uint8_t {
    WindowsCng = 0,
    WindowsCryptoApi,
    WindowsTrust,
    OpenSsl,
    Libsodium,
};

enum class VerificationReturnRule : uint8_t {
    ZeroIsVerified = 0,
    NonzeroIsVerified,
    OneIsVerified,
};

enum class VerificationArgumentRole : uint8_t {
    KeyOrContext = 0,
    PaddingInfo,
    DigestOrMessage,
    DigestOrMessageLength,
    Signature,
    SignatureLength,
    Flags,
    TrustAction,
    TrustData,
};

const char* VerificationApiFamilyText(VerificationApiFamily family);
const char* VerificationReturnRuleText(VerificationReturnRule rule);
const char* VerificationArgumentRoleText(VerificationArgumentRole role);

struct VerificationApiArgument {
    uint8_t index = 0; // zero-based ABI argument index
    VerificationArgumentRole role = VerificationArgumentRole::KeyOrContext;
};

struct VerificationApiMatch {
    std::string dll;            // normalized lower-case basename, no .dll
    std::string canonicalName;  // stable SDK/library spelling
    std::string normalizedName; // decoration-free lower-case exact key
    VerificationApiFamily family = VerificationApiFamily::WindowsCng;
    VerificationReturnRule returnRule = VerificationReturnRule::ZeroIsVerified;
    std::vector<VerificationApiArgument> arguments;

    // True only for APIs whose success contract directly says that the supplied
    // message/digest signature is valid. WinVerifyTrust is deliberately false:
    // its success is a policy/trust decision over WINTRUST_DATA and cannot by
    // itself be promoted to an application entitlement signature.
    bool directSignatureVerdict = false;
    bool trustPolicyVerdict = false;
    std::string meaning;
};

// Normalization is bounded. Oversized input becomes an empty key. A/W suffixes
// remain because they are part of the exact exported name.
std::string NormalizeVerificationDll(std::string_view dll);
std::string NormalizeVerificationApiName(std::string_view symbol);

// Exact module+symbol lookup. A module qualifier in `symbol` may supply an
// omitted `dll`; a conflicting explicit module is rejected.
std::optional<VerificationApiMatch> LookupVerificationApi(
    std::string_view dll, std::string_view symbol);

// Interpret a raw ABI return according to the documented success predicate.
// This says only that the API reported its own verification/trust operation as
// successful; it does not establish how the application used that result.
bool VerificationApiResultIsVerified(const VerificationApiMatch& api,
                                     uint64_t rawValue);

std::vector<VerificationApiMatch> EnumerateVerificationApis();

} // namespace ds
