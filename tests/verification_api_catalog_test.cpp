#include "Core/VerificationApiCatalog.h"

#include <cstdio>
#include <initializer_list>
#include <string>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static void checkArguments(
    const VerificationApiMatch& api,
    std::initializer_list<VerificationApiArgument> expected) {
    CHECK(api.arguments.size() == expected.size());
    size_t i = 0;
    for (const VerificationApiArgument& argument : expected) {
        if (i >= api.arguments.size()) break;
        CHECK(api.arguments[i].index == argument.index);
        CHECK(api.arguments[i].role == argument.role);
        ++i;
    }
}

int main() {
    const auto bcrypt = LookupVerificationApi(
        "C:\\Windows\\System32\\BCRYPT.DLL",
        "__imp_BCryptVerifySignature");
    CHECK(bcrypt.has_value());
    CHECK(bcrypt && bcrypt->family == VerificationApiFamily::WindowsCng);
    CHECK(bcrypt && bcrypt->directSignatureVerdict);
    CHECK(bcrypt && !bcrypt->trustPolicyVerdict);
    CHECK(bcrypt && bcrypt->arguments.size() == 7);
    if (bcrypt) {
        checkArguments(*bcrypt, {
            {0, VerificationArgumentRole::KeyOrContext},
            {1, VerificationArgumentRole::PaddingInfo},
            {2, VerificationArgumentRole::DigestOrMessage},
            {3, VerificationArgumentRole::DigestOrMessageLength},
            {4, VerificationArgumentRole::Signature},
            {5, VerificationArgumentRole::SignatureLength},
            {6, VerificationArgumentRole::Flags},
        });
    }
    CHECK(bcrypt && VerificationApiResultIsVerified(*bcrypt, 0));
    CHECK(bcrypt && !VerificationApiResultIsVerified(*bcrypt, 0xC000A000u));

    const auto crypto = LookupVerificationApi(
        "", "ADVAPI32.dll!_CryptVerifySignatureW@24");
    CHECK(crypto.has_value());
    CHECK(crypto && crypto->returnRule ==
          VerificationReturnRule::NonzeroIsVerified);
    CHECK(crypto && VerificationApiResultIsVerified(*crypto, 1));
    CHECK(crypto && !VerificationApiResultIsVerified(*crypto, 0));

    const auto trust = LookupVerificationApi("wintrust", "WinVerifyTrust");
    CHECK(trust.has_value());
    CHECK(trust && !trust->directSignatureVerdict);
    CHECK(trust && trust->trustPolicyVerdict);
    CHECK(trust && VerificationApiResultIsVerified(*trust, 0));

    const auto openssl = LookupVerificationApi(
        "libcrypto-3-x64.dll", "EVP_DigestVerifyFinal");
    CHECK(openssl.has_value());
    CHECK(openssl && openssl->family == VerificationApiFamily::OpenSsl);
    CHECK(openssl && VerificationApiResultIsVerified(*openssl, 1));
    CHECK(openssl && !VerificationApiResultIsVerified(*openssl, 0));
    CHECK(openssl && !VerificationApiResultIsVerified(
        *openssl, static_cast<uint64_t>(-1)));

    const auto sodium = LookupVerificationApi(
        "libsodium.dll", "crypto_sign_verify_detached");
    CHECK(sodium.has_value());
    CHECK(sodium && sodium->directSignatureVerdict);
    CHECK(sodium && VerificationApiResultIsVerified(*sodium, 0));

    CHECK(!LookupVerificationApi("user32", "BCryptVerifySignature"));
    CHECK(!LookupVerificationApi("bcrypt", "BCryptVerifySignatureEx"));
    CHECK(!LookupVerificationApi("evilcrypto", "EVP_PKEY_verify"));
    CHECK(!LookupVerificationApi("bcrypt", "advapi32!CryptVerifySignatureA"));
    CHECK(!LookupVerificationApi(std::string(2048, 'a'),
                                 "BCryptVerifySignature"));
    const auto catalog = EnumerateVerificationApis();
    CHECK(catalog.size() <= kVerificationApiCatalogHardMaxRows);

    // Every row must copy its exact argument metadata from lifetime-stable
    // catalog storage.  This catches the former MSVC failure where dangling
    // initializer_list backing arrays yielded only {0, KeyOrContext} entries.
    size_t knownRows = 0;
    for (const VerificationApiMatch& api : catalog) {
        if (api.normalizedName == "bcryptverifysignature" ||
            api.normalizedName == "ncryptverifysignature") {
            checkArguments(api, {
                {0, VerificationArgumentRole::KeyOrContext},
                {1, VerificationArgumentRole::PaddingInfo},
                {2, VerificationArgumentRole::DigestOrMessage},
                {3, VerificationArgumentRole::DigestOrMessageLength},
                {4, VerificationArgumentRole::Signature},
                {5, VerificationArgumentRole::SignatureLength},
                {6, VerificationArgumentRole::Flags},
            });
            ++knownRows;
        } else if (api.normalizedName == "cryptverifysignaturea" ||
                   api.normalizedName == "cryptverifysignaturew") {
            checkArguments(api, {
                {0, VerificationArgumentRole::KeyOrContext},
                {1, VerificationArgumentRole::Signature},
                {2, VerificationArgumentRole::SignatureLength},
                {3, VerificationArgumentRole::KeyOrContext},
            });
            ++knownRows;
        } else if (api.normalizedName == "winverifytrust") {
            checkArguments(api, {
                {1, VerificationArgumentRole::TrustAction},
                {2, VerificationArgumentRole::TrustData},
            });
            ++knownRows;
        } else if (api.normalizedName == "evp_digestverifyfinal") {
            checkArguments(api, {
                {0, VerificationArgumentRole::KeyOrContext},
                {1, VerificationArgumentRole::Signature},
                {2, VerificationArgumentRole::SignatureLength},
            });
            ++knownRows;
        } else if (api.normalizedName == "evp_pkey_verify") {
            checkArguments(api, {
                {0, VerificationArgumentRole::KeyOrContext},
                {1, VerificationArgumentRole::Signature},
                {2, VerificationArgumentRole::SignatureLength},
                {3, VerificationArgumentRole::DigestOrMessage},
                {4, VerificationArgumentRole::DigestOrMessageLength},
            });
            ++knownRows;
        } else if (api.normalizedName == "crypto_sign_verify_detached") {
            checkArguments(api, {
                {0, VerificationArgumentRole::Signature},
                {1, VerificationArgumentRole::DigestOrMessage},
                {2, VerificationArgumentRole::DigestOrMessageLength},
                {3, VerificationArgumentRole::KeyOrContext},
            });
            ++knownRows;
        } else {
            CHECK(false && "catalog row lacks an exact argument regression");
        }
    }
    CHECK(knownRows == catalog.size());

    CHECK(std::string(VerificationReturnRuleText(
              VerificationReturnRule::OneIsVerified)) ==
          "exactly one means verified");
    CHECK(std::string(VerificationArgumentRoleText(
              VerificationArgumentRole::Signature)) == "signature");

    if (failures) return 1;
    std::puts("verification API catalog tests passed");
    return 0;
}
