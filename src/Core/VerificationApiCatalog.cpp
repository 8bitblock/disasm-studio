#include "VerificationApiCatalog.h"

#include <algorithm>
#include <array>
#include <cctype>

namespace ds {
namespace {

struct CatalogRow {
    std::string_view dll;
    std::string_view key;
    std::string_view canonical;
    VerificationApiFamily family;
    VerificationReturnRule returnRule;
    bool directSignatureVerdict;
    bool trustPolicyVerdict;
    const VerificationApiArgument* arguments;
    size_t argumentCount;
    std::string_view meaning;
};

constexpr VerificationApiArgument arg(uint8_t index,
                                      VerificationArgumentRole role) {
    return {index, role};
}

// CatalogRow must not retain std::initializer_list instances.  Their backing
// arrays are temporary objects and MSVC does not extend those arrays' lifetime
// when the initializer_list is stored as an aggregate member.  Keep every
// signature in named static storage and let rows carry a pointer/count view.
constexpr std::array kCngVerifyArguments = {
    arg(0, VerificationArgumentRole::KeyOrContext),
    arg(1, VerificationArgumentRole::PaddingInfo),
    arg(2, VerificationArgumentRole::DigestOrMessage),
    arg(3, VerificationArgumentRole::DigestOrMessageLength),
    arg(4, VerificationArgumentRole::Signature),
    arg(5, VerificationArgumentRole::SignatureLength),
    arg(6, VerificationArgumentRole::Flags),
};

constexpr std::array kCryptoApiVerifyArguments = {
    arg(0, VerificationArgumentRole::KeyOrContext),
    arg(1, VerificationArgumentRole::Signature),
    arg(2, VerificationArgumentRole::SignatureLength),
    arg(3, VerificationArgumentRole::KeyOrContext),
};

constexpr std::array kWinTrustArguments = {
    arg(1, VerificationArgumentRole::TrustAction),
    arg(2, VerificationArgumentRole::TrustData),
};

constexpr std::array kOpenSslDigestVerifyArguments = {
    arg(0, VerificationArgumentRole::KeyOrContext),
    arg(1, VerificationArgumentRole::Signature),
    arg(2, VerificationArgumentRole::SignatureLength),
};

constexpr std::array kOpenSslPkeyVerifyArguments = {
    arg(0, VerificationArgumentRole::KeyOrContext),
    arg(1, VerificationArgumentRole::Signature),
    arg(2, VerificationArgumentRole::SignatureLength),
    arg(3, VerificationArgumentRole::DigestOrMessage),
    arg(4, VerificationArgumentRole::DigestOrMessageLength),
};

constexpr std::array kSodiumVerifyArguments = {
    arg(0, VerificationArgumentRole::Signature),
    arg(1, VerificationArgumentRole::DigestOrMessage),
    arg(2, VerificationArgumentRole::DigestOrMessageLength),
    arg(3, VerificationArgumentRole::KeyOrContext),
};

template <size_t N>
constexpr const VerificationApiArgument* argumentData(
    const std::array<VerificationApiArgument, N>& arguments) {
    return arguments.data();
}

template <size_t N>
constexpr size_t argumentCount(
    const std::array<VerificationApiArgument, N>&) {
    return N;
}

// Keep module spellings exact. OpenSSL deliberately has a bounded list of
// common upstream Windows basenames instead of accepting an arbitrary DLL that
// happens to export a familiar symbol.
constexpr CatalogRow kRows[] = {
    {"bcrypt", "bcryptverifysignature", "BCryptVerifySignature",
     VerificationApiFamily::WindowsCng,
     VerificationReturnRule::ZeroIsVerified, true, false,
     argumentData(kCngVerifyArguments), argumentCount(kCngVerifyArguments),
     "STATUS_SUCCESS means the supplied signature is valid for the supplied hash and key"},
    {"advapi32", "cryptverifysignaturea", "CryptVerifySignatureA",
     VerificationApiFamily::WindowsCryptoApi,
     VerificationReturnRule::NonzeroIsVerified, true, false,
     argumentData(kCryptoApiVerifyArguments),
     argumentCount(kCryptoApiVerifyArguments),
     "nonzero means the signature was verified by the CryptoAPI hash/key context"},
    {"advapi32", "cryptverifysignaturew", "CryptVerifySignatureW",
     VerificationApiFamily::WindowsCryptoApi,
     VerificationReturnRule::NonzeroIsVerified, true, false,
     argumentData(kCryptoApiVerifyArguments),
     argumentCount(kCryptoApiVerifyArguments),
     "nonzero means the signature was verified by the CryptoAPI hash/key context"},
    {"ncrypt", "ncryptverifysignature", "NCryptVerifySignature",
     VerificationApiFamily::WindowsCng,
     VerificationReturnRule::ZeroIsVerified, true, false,
     argumentData(kCngVerifyArguments), argumentCount(kCngVerifyArguments),
     "ERROR_SUCCESS means the supplied signature is valid for the supplied hash and key"},
    {"wintrust", "winverifytrust", "WinVerifyTrust",
     VerificationApiFamily::WindowsTrust,
     VerificationReturnRule::ZeroIsVerified, false, true,
     argumentData(kWinTrustArguments), argumentCount(kWinTrustArguments),
     "zero means the requested WinTrust policy accepted the supplied trust data; this is not automatically an entitlement verdict"},

    {"libcrypto", "evp_digestverifyfinal", "EVP_DigestVerifyFinal",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslDigestVerifyArguments),
     argumentCount(kOpenSslDigestVerifyArguments),
     "one means the OpenSSL digest signature verified; zero is invalid and negative is an error"},
    {"libcrypto-1_1", "evp_digestverifyfinal", "EVP_DigestVerifyFinal",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslDigestVerifyArguments),
     argumentCount(kOpenSslDigestVerifyArguments),
     "one means the OpenSSL digest signature verified; zero is invalid and negative is an error"},
    {"libcrypto-1_1-x64", "evp_digestverifyfinal", "EVP_DigestVerifyFinal",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslDigestVerifyArguments),
     argumentCount(kOpenSslDigestVerifyArguments),
     "one means the OpenSSL digest signature verified; zero is invalid and negative is an error"},
    {"libcrypto-3", "evp_digestverifyfinal", "EVP_DigestVerifyFinal",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslDigestVerifyArguments),
     argumentCount(kOpenSslDigestVerifyArguments),
     "one means the OpenSSL digest signature verified; zero is invalid and negative is an error"},
    {"libcrypto-3-x64", "evp_digestverifyfinal", "EVP_DigestVerifyFinal",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslDigestVerifyArguments),
     argumentCount(kOpenSslDigestVerifyArguments),
     "one means the OpenSSL digest signature verified; zero is invalid and negative is an error"},

    {"libcrypto", "evp_pkey_verify", "EVP_PKEY_verify",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslPkeyVerifyArguments),
     argumentCount(kOpenSslPkeyVerifyArguments),
     "one means the OpenSSL public-key signature verified; zero is invalid and negative is an error"},
    {"libcrypto-1_1", "evp_pkey_verify", "EVP_PKEY_verify",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslPkeyVerifyArguments),
     argumentCount(kOpenSslPkeyVerifyArguments),
     "one means the OpenSSL public-key signature verified; zero is invalid and negative is an error"},
    {"libcrypto-1_1-x64", "evp_pkey_verify", "EVP_PKEY_verify",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslPkeyVerifyArguments),
     argumentCount(kOpenSslPkeyVerifyArguments),
     "one means the OpenSSL public-key signature verified; zero is invalid and negative is an error"},
    {"libcrypto-3", "evp_pkey_verify", "EVP_PKEY_verify",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslPkeyVerifyArguments),
     argumentCount(kOpenSslPkeyVerifyArguments),
     "one means the OpenSSL public-key signature verified; zero is invalid and negative is an error"},
    {"libcrypto-3-x64", "evp_pkey_verify", "EVP_PKEY_verify",
     VerificationApiFamily::OpenSsl,
     VerificationReturnRule::OneIsVerified, true, false,
     argumentData(kOpenSslPkeyVerifyArguments),
     argumentCount(kOpenSslPkeyVerifyArguments),
     "one means the OpenSSL public-key signature verified; zero is invalid and negative is an error"},

    {"libsodium", "crypto_sign_verify_detached", "crypto_sign_verify_detached",
     VerificationApiFamily::Libsodium,
     VerificationReturnRule::ZeroIsVerified, true, false,
     argumentData(kSodiumVerifyArguments),
     argumentCount(kSodiumVerifyArguments),
     "zero means the detached Ed25519 signature is valid for the message and public key"},
};

static_assert(std::size(kRows) <= kVerificationApiCatalogHardMaxRows);

std::string lower(std::string_view value, size_t cap) {
    if (value.size() > kVerificationLookupFieldMaxBytes || value.size() > cap)
        return {};
    std::string result(value);
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

VerificationApiMatch makeMatch(const CatalogRow& row) {
    VerificationApiMatch result;
    result.dll.assign(row.dll);
    result.canonicalName.assign(row.canonical);
    result.normalizedName.assign(row.key);
    result.family = row.family;
    result.returnRule = row.returnRule;
    result.arguments.assign(row.arguments, row.arguments + row.argumentCount);
    result.directSignatureVerdict = row.directSignatureVerdict;
    result.trustPolicyVerdict = row.trustPolicyVerdict;
    result.meaning.assign(row.meaning);
    return result;
}

} // namespace

const char* VerificationApiFamilyText(VerificationApiFamily family) {
    switch (family) {
    case VerificationApiFamily::WindowsCng:       return "Windows CNG";
    case VerificationApiFamily::WindowsCryptoApi: return "Windows CryptoAPI";
    case VerificationApiFamily::WindowsTrust:     return "Windows trust policy";
    case VerificationApiFamily::OpenSsl:          return "OpenSSL";
    case VerificationApiFamily::Libsodium:        return "libsodium";
    }
    return "unknown";
}

const char* VerificationReturnRuleText(VerificationReturnRule rule) {
    switch (rule) {
    case VerificationReturnRule::ZeroIsVerified:    return "zero means verified";
    case VerificationReturnRule::NonzeroIsVerified: return "nonzero means verified";
    case VerificationReturnRule::OneIsVerified:     return "exactly one means verified";
    }
    return "unknown";
}

const char* VerificationArgumentRoleText(VerificationArgumentRole role) {
    switch (role) {
    case VerificationArgumentRole::KeyOrContext:          return "key/context";
    case VerificationArgumentRole::PaddingInfo:           return "padding info";
    case VerificationArgumentRole::DigestOrMessage:       return "digest/message";
    case VerificationArgumentRole::DigestOrMessageLength: return "digest/message length";
    case VerificationArgumentRole::Signature:             return "signature";
    case VerificationArgumentRole::SignatureLength:       return "signature length";
    case VerificationArgumentRole::Flags:                 return "flags";
    case VerificationArgumentRole::TrustAction:           return "trust action";
    case VerificationArgumentRole::TrustData:             return "trust data";
    }
    return "unknown";
}

std::string NormalizeVerificationDll(std::string_view dll) {
    if (dll.size() > kVerificationLookupFieldMaxBytes) return {};
    const size_t slash = dll.find_last_of("/\\");
    if (slash != std::string_view::npos) dll.remove_prefix(slash + 1);
    std::string result = lower(dll, kVerificationNormalizedDllMaxBytes);
    if (result.size() > 4 && result.compare(result.size() - 4, 4, ".dll") == 0)
        result.resize(result.size() - 4);
    return result;
}

std::string NormalizeVerificationApiName(std::string_view symbol) {
    if (symbol.size() > kVerificationLookupFieldMaxBytes) return {};
    const size_t bang = symbol.find_last_of('!');
    if (bang != std::string_view::npos) symbol.remove_prefix(bang + 1);
    if (symbol.rfind("__imp_", 0) == 0) symbol.remove_prefix(6);
    else if (symbol.rfind("_imp__", 0) == 0) symbol.remove_prefix(6);
    while (!symbol.empty() && (symbol.front() == '_' || symbol.front() == '@'))
        symbol.remove_prefix(1);
    const size_t at = symbol.find_last_of('@');
    if (at != std::string_view::npos && at + 1 < symbol.size() &&
        std::all_of(symbol.begin() + static_cast<std::ptrdiff_t>(at + 1),
                    symbol.end(), [](unsigned char c) { return std::isdigit(c) != 0; }))
        symbol = symbol.substr(0, at);
    return lower(symbol, kVerificationNormalizedSymbolMaxBytes);
}

std::optional<VerificationApiMatch> LookupVerificationApi(
    std::string_view dll, std::string_view symbol) {
    if (dll.size() > kVerificationLookupFieldMaxBytes ||
        symbol.size() > kVerificationLookupFieldMaxBytes)
        return std::nullopt;

    std::string symbolDll;
    const size_t bang = symbol.find_last_of('!');
    if (bang != std::string_view::npos) {
        symbolDll = NormalizeVerificationDll(symbol.substr(0, bang));
        if (symbolDll.empty()) return std::nullopt;
    }
    std::string normalizedDll = NormalizeVerificationDll(dll);
    if (normalizedDll.empty()) normalizedDll = symbolDll;
    else if (!symbolDll.empty() && normalizedDll != symbolDll) return std::nullopt;
    const std::string normalizedName = NormalizeVerificationApiName(symbol);
    if (normalizedDll.empty() || normalizedName.empty()) return std::nullopt;

    for (const CatalogRow& row : kRows)
        if (row.dll == normalizedDll && row.key == normalizedName)
            return makeMatch(row);
    return std::nullopt;
}

bool VerificationApiResultIsVerified(const VerificationApiMatch& api,
                                     uint64_t rawValue) {
    switch (api.returnRule) {
    case VerificationReturnRule::ZeroIsVerified:    return rawValue == 0;
    case VerificationReturnRule::NonzeroIsVerified: return rawValue != 0;
    case VerificationReturnRule::OneIsVerified:     return rawValue == 1;
    }
    return false;
}

std::vector<VerificationApiMatch> EnumerateVerificationApis() {
    std::vector<VerificationApiMatch> result;
    result.reserve(std::size(kRows));
    for (const CatalogRow& row : kRows) result.push_back(makeMatch(row));
    return result;
}

} // namespace ds
