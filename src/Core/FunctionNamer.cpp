#include "FunctionNamer.h"
#include "BinaryFile.h"
#include "../Disasm/IDisassembler.h"
#include "InstructionReference.h"   // instrDataRef/instrImmRef: referenced data addresses
#include "StringActionEvidence.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <initializer_list>
#include <unordered_map>
#include <unordered_set>

namespace ds {
namespace {

// Lowercase + strip leading underscores so "__imp_CreateFileW", "_malloc" and
// "CreateFileW" all compare uniformly.
std::string norm(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (char c : s) o.push_back((char)std::tolower((unsigned char)c));
    size_t i = 0; while (i < o.size() && o[i] == '_') ++i;
    return o.substr(i);
}

// Runtime/compiler-emitted helpers that never tell us what a function *does*.
bool isNoiseApi(const std::string& n) {
    static const char* kNoise[] = {
        "security_check_cookie", "security_cookie", "stack_chk_fail", "chkstk",
        "gshandlercheck", "cxxframehandler", "except_handler", "rtc_",
        "guard_check_icall", "guard_dispatch_icall", "guard_",
    };
    std::string low = norm(n);
    for (const char* t : kNoise) if (low.find(t) != std::string::npos) return true;
    return false;
}

// Bare API name from a possibly-qualified "dll.func" (and reject ordinals).
std::string bareApi(const std::string& full) {
    if (full.empty()) return "";
    size_t dot = full.rfind('.');
    std::string n = (dot == std::string::npos) ? full : full.substr(dot + 1);
    // BinaryFile spells ordinal-only PE imports as "#123".  Older producers may
    // use "ordinal_123"; neither carries semantic naming evidence.
    if (n.empty() || n[0] == '#' || norm(n).rfind("ordinal", 0) == 0) return "";
    return n;
}

bool isIdentifier(const std::string& s) {
    if (s.empty() || !(std::isalpha((unsigned char)s[0]) || s[0] == '_')) return false;
    for (char c : s)
        if (!(std::isalnum((unsigned char)c) || c == '_')) return false;
    return true;
}

// FunctionAnalyzer's anonymous names have one exact shape.  Merely starting
// with "sub_" is not enough: a real export such as sub_handler must survive.
bool isAnonymousSubName(const std::string& s) {
    if (s.size() <= 4 || s.rfind("sub_", 0) != 0) return false;
    for (size_t i = 4; i < s.size(); ++i)
        if (!std::isxdigit((unsigned char)s[i])) return false;
    return true;
}

// Case-insensitive allocation avoids visually ambiguous guesses beside PE/PDB
// names ("Read_File" and "read_file") while preserving the chosen spelling.
std::string nameKey(const std::string& s) {
    std::string k; k.reserve(s.size());
    for (char c : s) k.push_back((char)std::tolower((unsigned char)c));
    return k;
}

// Remove the import-pointer and x86 calling-convention decorations while
// retaining the API's useful display case.  Real PE/PDB spellings include
// combinations such as __imp__Foo@8, @Foo@8, and __imp_@Foo@8.
std::string undecoratedImportName(const std::string& full) {
    std::string n = bareApi(full);
    if (size_t bang = n.rfind('!'); bang != std::string::npos) n.erase(0, bang + 1);

    bool changed = true;
    while (changed) {
        changed = false;
        while (!n.empty() && n.front() == '_') { n.erase(n.begin()); changed = true; }
        if (nameKey(n).rfind("imp_", 0) == 0) { n.erase(0, 4); changed = true; }
    }
    if (!n.empty() && n.front() == '@') n.erase(n.begin()); // leading fastcall decoration
    while (!n.empty() && n.front() == '_') n.erase(n.begin());

    if (size_t at = n.rfind('@'); at != std::string::npos && at > 0 && at + 1 < n.size()) {
        bool byteCount = true;
        for (size_t i = at + 1; i < n.size(); ++i)
            if (!std::isdigit(static_cast<unsigned char>(n[i]))) { byteCount = false; break; }
        if (byteCount) n.resize(at);
    }
    if (n.empty() || n.front() == '#' || norm(n).rfind("ordinal", 0) == 0) return {};
    return n;
}

// Strip import-pointer and stdcall decoration without changing the API's useful
// display case.  Used for j_<API> thunk names.
std::string thunkIdentifier(const std::string& full) {
    std::string n = undecoratedImportName(full);
    if (n.empty() || n[0] == '?') return {};             // MSVC-mangled tail: no safe short name

    std::string out;
    for (char c : n) {
        if (std::isalnum((unsigned char)c) || c == '_') out.push_back(c);
        else if (!out.empty() && out.back() != '_')     out.push_back('_');
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    if (out.empty()) return {};
    if (std::isdigit((unsigned char)out[0])) out = "fn_" + out;
    return isIdentifier(out) ? out : std::string();
}

std::string joinApis(const std::vector<std::string>& v) {
    std::string r; int n = 0;
    for (const auto& a : v) {
        if (n >= 4) { r += ", ..."; break; }
        if (n++) r += ", ";
        r += a;
    }
    return r;
}

// Decoration-insensitive but otherwise exact API key.  Substring matching is
// intentionally forbidden here: ConnectNamedPipe and SendMessage are not
// network availability/transport evidence.  PE import spellings may include a
// DLL qualifier, __imp_, stdcall @N decoration, or an A/W suffix.
std::string compactApiKey(const std::string& full) {
    const std::string n = undecoratedImportName(full);

    std::string key;
    key.reserve(n.size());
    for (char c : n)
        if (std::isalnum((unsigned char)c))
            key.push_back((char)std::tolower((unsigned char)c));
    return key;
}

bool exactApiOrAnsiWideVariant(const std::string& key, const char* base) {
    const std::string b = base;
    return key == b || key == b + "a" || key == b + "w";
}

bool isConnectivityPredicateApi(const std::string& api) {
    const std::string key = compactApiKey(api);
    return exactApiOrAnsiWideVariant(key, "internetgetconnectedstate") ||
           exactApiOrAnsiWideVariant(key, "internetgetconnectedstateex") ||
           exactApiOrAnsiWideVariant(key, "internetcheckconnection") ||
           exactApiOrAnsiWideVariant(key, "isnetworkalive") ||
           exactApiOrAnsiWideVariant(key, "isdestinationreachable");
}

// Any real resolution/session/transport/payload work makes the enclosing
// function broader than a connectivity predicate.  Keep this an exact catalog
// local to FunctionNamer rather than reintroducing the old substring hazards.
bool isTransportOrPayloadApi(const std::string& api) {
    const std::string key = compactApiKey(api);
    static constexpr const char* kNetworkWork[] = {
        "socket", "wsasocket", "wsastartup", "wsacleanup", "connect",
        "connectex", "wsaconnect", "bind", "listen", "accept", "acceptex",
        "closesocket", "send", "sendto", "wsasend", "wsasendto",
        "transmitfile", "recv", "recvfrom", "wsarecv", "wsarecvfrom",
        "getaddrinfo", "getaddrinfoex", "gethostbyname", "gethostbyaddr",
        "getnameinfo", "dnsquery", "internetattemptconnect", "internetopen",
        "internetconnect", "internetopenurl", "httpopenrequest",
        "httpsendrequest", "httpsendrequestex", "internetwritefile",
        "httpendrequest", "internetreadfile", "internetreadfileex",
        "httpqueryinfo", "internetclosehandle", "winhttpopen",
        "winhttpconnect", "winhttpopenrequest", "winhttpsendrequest",
        "winhttpwritedata", "winhttpreceiveresponse", "winhttpreaddata",
        "winhttpqueryheaders", "winhttpclosehandle", "urldownloadtofile",
    };
    for (const char* candidate : kNetworkWork)
        if (exactApiOrAnsiWideVariant(key, candidate)) return true;
    return false;
}

std::string connectivityPredicateIn(const std::vector<std::string>& apis) {
    for (const std::string& api : apis) {
        if (!isConnectivityPredicateApi(api)) continue;
        if (std::string display = thunkIdentifier(api); !display.empty()) return display;
        return bareApi(api);
    }
    return {};
}

bool hasTransportOrPayloadApi(const std::vector<std::string>& apis) {
    for (const std::string& api : apis)
        if (isTransportOrPayloadApi(api)) return true;
    return false;
}

bool hasOnlyConnectivityPredicateApis(const std::vector<std::string>& apis) {
    return !apis.empty() &&
           std::all_of(apis.begin(), apis.end(), isConnectivityPredicateApi);
}

// Contextual names deliberately require two independent signals: a strong
// subject phrase from this function and an exact, complete operation shape.
// This keeps generic helpers generic while allowing useful analyst-facing names
// such as licenseHashing and configDecryption when the evidence really agrees.
enum class SemanticSubject {
    None,
    License,
    Serial,
    Password,
    Credential,
    Config,
    Payload,
    Token,
    Integrity,
};

struct SubjectEvidence {
    SemanticSubject subject = SemanticSubject::None;
    std::string cue;
    bool ambiguous = false;
    bool encryptionCue = false;
    bool compressionCue = false;
};

std::string lowerText(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text)
        out.push_back((char)std::tolower((unsigned char)c));
    return out;
}

// Lowercase, collapse punctuation/whitespace, and pad with spaces so phrase
// lookup is word-bounded ("sublicense" never matches "license").
std::string normalizedWords(const std::string& text) {
    std::string out = " ";
    bool spaced = true;
    for (char c : text) {
        const unsigned char u = (unsigned char)c;
        if (std::isalnum(u)) {
            out.push_back((char)std::tolower(u));
            spaced = false;
        } else if (!spaced) {
            out.push_back(' ');
            spaced = true;
        }
    }
    if (!spaced) out.push_back(' ');
    return out;
}

bool containsPhrase(const std::string& words, const char* phrase) {
    return words.find(std::string(" ") + phrase + " ") != std::string::npos;
}

const char* firstPhrase(const std::string& words,
                        std::initializer_list<const char*> phrases) {
    for (const char* phrase : phrases)
        if (containsPhrase(words, phrase)) return phrase;
    return nullptr;
}

bool containsBoundedExtension(const std::string& lower, const char* extension) {
    const size_t length = std::char_traits<char>::length(extension);
    for (size_t pos = lower.find(extension); pos != std::string::npos;
         pos = lower.find(extension, pos + 1)) {
        const size_t end = pos + length;
        if (end == lower.size()) return true;
        const unsigned char next = (unsigned char)lower[end];
        if (!std::isalnum(next) && next != '_' && next != '.') return true;
    }
    return false;
}

SubjectEvidence contextualSubject(const std::vector<std::string>& strings) {
    SubjectEvidence result;
    auto add = [&](SemanticSubject subject, const char* cue) {
        if (!cue || result.ambiguous) return;
        if (result.subject == SemanticSubject::None) {
            result.subject = subject;
            result.cue = cue;
        } else if (result.subject != subject) {
            result.ambiguous = true;
            result.subject = SemanticSubject::None;
            result.cue.clear();
        }
    };

    for (const std::string& text : strings) {
        const std::string words = normalizedWords(text);
        const std::string lower = lowerText(text);
        if (firstPhrase(words, {"encrypted", "encrypt", "encryption",
                                "decrypt", "decryption"}))
            result.encryptionCue = true;
        if (firstPhrase(words, {"compressed", "decompress", "decompression",
                                "packed data", "archive data"}))
            result.compressionCue = true;

        // Legal boilerplate is not product-key evidence.  Skip only license
        // cues in this string so an unrelated strong subject can still count.
        const bool legalLicenseText = firstPhrase(words, {
            "license agreement", "licence agreement", "software license",
            "software licence", "third party license", "third party licence",
            "licensed under", "licenced under", "open source license",
        }) != nullptr;
        if (!legalLicenseText) {
            add(SemanticSubject::License, firstPhrase(words, {
                "license key", "licence key", "product key", "activation key",
                "activation code", "registration key", "registration code",
                "invalid license", "invalid licence", "expired license",
                "expired licence", "license expired", "licence expired",
                "valid license", "valid licence", "validate license",
                "validate licence", "license validation", "licence validation",
                "license hash", "licence hash", "license digest", "licence digest",
            }));
        }

        const bool deviceSerial = firstPhrase(words, {
            "device serial", "hardware serial", "volume serial", "drive serial",
            "disk serial", "serial port",
        }) != nullptr;
        if (!deviceSerial) {
            add(SemanticSubject::Serial, firstPhrase(words, {
                "serial number", "serial key", "serial code", "enter serial",
                "invalid serial", "valid serial", "validate serial",
                "serial validation", "serial hash", "serial digest",
            }));
        }

        add(SemanticSubject::Password, firstPhrase(words, {
            "password", "passwd", "passcode", "password hash", "password digest",
        }));
        add(SemanticSubject::Credential, firstPhrase(words, {
            "user credential", "login credential", "stored credential",
            "credential hash", "credential digest",
        }));
        add(SemanticSubject::Config, firstPhrase(words, {
            "config", "configuration", "encrypted config", "encrypted configuration",
            "application settings", "user settings", "preferences file",
        }));
        if (containsBoundedExtension(lower, ".ini") ||
            containsBoundedExtension(lower, ".cfg") ||
            lower.find("config.json") != std::string::npos)
            add(SemanticSubject::Config, "configuration file");

        add(SemanticSubject::Payload, firstPhrase(words, {
            "payload", "compressed payload", "encrypted payload",
            "compressed data", "archive data", "packed data",
        }));
        add(SemanticSubject::Token, firstPhrase(words, {
            "access token", "auth token", "authentication token", "session token",
            "refresh token", "bearer token", "api token", "csrf token",
        }));
        add(SemanticSubject::Integrity, firstPhrase(words, {
            "integrity check", "integrity verification", "digital signature",
            "file signature", "trusted publisher", "certificate chain",
            "signature verification",
        }));
    }
    return result;
}

const char* subjectStem(SemanticSubject subject) {
    switch (subject) {
    case SemanticSubject::License:    return "license";
    case SemanticSubject::Serial:     return "serial";
    case SemanticSubject::Password:   return "password";
    case SemanticSubject::Credential: return "credential";
    case SemanticSubject::Config:     return "config";
    case SemanticSubject::Payload:    return "payload";
    case SemanticSubject::Token:      return "token";
    case SemanticSubject::Integrity:  return "integrity";
    default:                          return "";
    }
}

bool keyIs(const std::string& key, std::initializer_list<const char*> candidates) {
    for (const char* candidate : candidates)
        if (key == candidate) return true;
    return false;
}

template <typename Predicate>
std::string firstApiMatching(const std::vector<std::string>& apis, Predicate predicate) {
    for (const std::string& api : apis)
        if (predicate(compactApiKey(api)))
            return undecoratedImportName(api);
    return {};
}

bool hasApiKey(const std::vector<std::string>& apis, const char* wanted) {
    return !firstApiMatching(apis, [&](const std::string& key) {
        return key == wanted;
    }).empty();
}

struct HashWorkflowEvidence {
    bool complete = false;
    std::string detail;
};

bool orderedApiStages(
    const std::vector<std::string>& calls,
    std::initializer_list<std::initializer_list<const char*>> stages) {
    size_t next = 0;
    for (const auto& stage : stages) {
        bool found = false;
        while (next < calls.size()) {
            const std::string key = compactApiKey(calls[next++]);
            if (keyIs(key, stage)) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

HashWorkflowEvidence hashWorkflow(const std::vector<std::string>& apis,
                                  const std::vector<std::string>& calls) {
    auto any = [&](std::initializer_list<const char*> keys) {
        for (const char* key : keys)
            if (hasApiKey(apis, key)) return true;
        return false;
    };

    if (orderedApiStages(calls, {
            {"cryptcreatehash"}, {"crypthashdata"}, {"cryptgethashparam"}}))
        return {true, "complete CryptoAPI hash pipeline (CryptCreateHash, CryptHashData, CryptGetHashParam)"};
    if (orderedApiStages(calls, {
            {"bcryptcreatehash"}, {"bcrypthashdata"}, {"bcryptfinishhash"}}))
        return {true, "complete CNG hash pipeline (BCryptCreateHash, BCryptHashData, BCryptFinishHash)"};
    if (hasApiKey(apis, "bcrypthash"))
        return {true, "one-shot BCryptHash operation"};

    if (orderedApiStages(calls, {
            {"evpdigestinit", "evpdigestinitex"},
            {"evpdigestupdate"},
            {"evpdigestfinal", "evpdigestfinalex"}}))
        return {true, "complete EVP digest pipeline"};

    struct LowLevelHash {
        const char* init;
        const char* update;
        const char* final;
        const char* label;
    };
    static constexpr LowLevelHash kLowLevel[] = {
        {"sha1init", "sha1update", "sha1final", "complete SHA-1 hash pipeline"},
        {"sha256init", "sha256update", "sha256final", "complete SHA-256 hash pipeline"},
        {"sha512init", "sha512update", "sha512final", "complete SHA-512 hash pipeline"},
        {"md5init", "md5update", "md5final", "complete MD5 hash pipeline"},
        {"ccsha1init", "ccsha1update", "ccsha1final", "complete CommonCrypto SHA-1 pipeline"},
        {"ccsha256init", "ccsha256update", "ccsha256final", "complete CommonCrypto SHA-256 pipeline"},
        {"ccsha512init", "ccsha512update", "ccsha512final", "complete CommonCrypto SHA-512 pipeline"},
        {"ccmd5init", "ccmd5update", "ccmd5final", "complete CommonCrypto MD5 pipeline"},
        {"cryptogenerichashinit", "cryptogenerichashupdate", "cryptogenerichashfinal",
         "complete libsodium generic-hash pipeline"},
    };
    for (const auto& workflow : kLowLevel)
        if (orderedApiStages(calls, {
                {workflow.init}, {workflow.update}, {workflow.final}}))
            return {true, workflow.label};

    if (any({"sha1", "sha256", "sha512", "md5", "ccsha1", "ccsha256",
             "ccsha512", "ccmd5", "cryptogenerichash"}))
        return {true, "one-shot cryptographic hash operation"};
    return {};
}

bool isComparatorApiKey(const std::string& key) {
    return keyIs(key, {
        "memcmp", "strcmp", "strncmp", "wcscmp", "wcsncmp", "stricmp",
        "wcsicmp", "lstrcmp", "lstrcmpa", "lstrcmpw", "lstrcmpi",
        "lstrcmpia", "lstrcmpiw", "cryptomemcmp", "sodiummemcmp",
    });
}

bool isCryptographicVerifierApiKey(const std::string& key) {
    return keyIs(key, {
        "cryptverifysignature", "cryptverifysignaturea", "cryptverifysignaturew",
        "bcryptverifysignature", "ncryptverifysignature", "evpdigestverifyfinal",
        "rsaverify", "ecdsaverify",
    });
}

bool isTrustVerifierApiKey(const std::string& key) {
    return key == "winverifytrust";
}

template <typename Predicate>
std::string resultDecisionApi(const FuncEvidence& e, Predicate predicate,
                              bool acceptDirectReturn) {
    for (const auto& use : e.apiResultUses) {
        if (!predicate(compactApiKey(use.api))) continue;
        if (use.checked || use.normalizedReturned ||
            (acceptDirectReturn && use.returned))
            return undecoratedImportName(use.api);
    }
    return {};
}

struct OperationWorkflowEvidence {
    bool complete = false;
    std::string detail;
};

OperationWorkflowEvidence decryptWorkflow(const std::vector<std::string>& apis,
                                          const std::vector<std::string>& calls) {
    const std::string oneShot = firstApiMatching(apis, [](const std::string& key) {
        return keyIs(key, {
            "cryptdecrypt", "bcryptdecrypt", "ncryptdecrypt", "aesdecrypt",
            "cryptunprotectdata", "cryptosecretboxopeneasy",
        });
    });
    if (!oneShot.empty()) return {true, "calls exact decryption API " + oneShot};
    if (orderedApiStages(calls, {
            {"evpdecryptinit", "evpdecryptinitex"},
            {"evpdecryptupdate"},
            {"evpdecryptfinal", "evpdecryptfinalex"}}))
        return {true, "complete EVP decryption pipeline"};
    return {};
}

OperationWorkflowEvidence encryptWorkflow(const std::vector<std::string>& apis,
                                          const std::vector<std::string>& calls) {
    const std::string oneShot = firstApiMatching(apis, [](const std::string& key) {
        return keyIs(key, {
            "cryptencrypt", "bcryptencrypt", "ncryptencrypt", "aesencrypt",
            "cryptprotectdata", "cryptosecretboxeasy",
        });
    });
    if (!oneShot.empty()) return {true, "calls exact encryption API " + oneShot};
    if (orderedApiStages(calls, {
            {"evpencryptinit", "evpencryptinitex"},
            {"evpencryptupdate"},
            {"evpencryptfinal", "evpencryptfinalex"}}))
        return {true, "complete EVP encryption pipeline"};
    return {};
}

bool isDecompressApiKey(const std::string& key) {
    return keyIs(key, {
        "rtldecompressbuffer", "rtldecompressbufferex", "decompress", "uncompress",
        "uncompress2", "inflate", "lz4decompress", "lz4decompresssafe",
        "zstddecompress", "zstddecompressdc", "zstddecompressstream",
    });
}

bool isRandomGenerationApiKey(const std::string& key) {
    return keyIs(key, {
        "bcryptgenrandom", "cryptgenrandom", "randbytes", "randprivbytes",
        "secrandomcopybytes", "randombytesbuf",
    });
}

bool isContextualVetoApi(const std::string& api) {
    if (isTransportOrPayloadApi(api)) return true;
    const std::string key = compactApiKey(api);
    return keyIs(key, {
        "createprocess", "createprocessa", "createprocessw", "shellexecute",
        "shellexecutea", "shellexecutew", "winexec", "system",
        "writeprocessmemory", "readprocessmemory", "virtualallocex",
        "createremotethread", "ntcreatethreadex", "queueuserapc",
    });
}

bool hasContextualVetoApi(const std::vector<std::string>& apis) {
    return std::any_of(apis.begin(), apis.end(), isContextualVetoApi);
}

bool supportsValidation(SemanticSubject subject) {
    return subject == SemanticSubject::License ||
           subject == SemanticSubject::Serial ||
           subject == SemanticSubject::Password ||
           subject == SemanticSubject::Credential ||
           subject == SemanticSubject::Token;
}

bool supportsHashing(SemanticSubject subject) {
    return supportsValidation(subject) || subject == SemanticSubject::Integrity;
}

GuessedName contextualSemanticGuess(const FuncEvidence& e) {
    GuessedName guess;
    const SubjectEvidence subject = contextualSubject(e.strings);
    constexpr int kMaxContextInstructions = 128;
    constexpr int kMaxContextCalls = 12;
    if (e.bodySampled || subject.ambiguous || subject.subject == SemanticSubject::None ||
        e.instrCount <= 0 || e.callCount <= 0 ||
        e.instrCount > kMaxContextInstructions || e.callCount > kMaxContextCalls ||
        hasContextualVetoApi(e.apis))
        return guess;

    const std::vector<std::string>& calls = e.apiCallSequence.empty()
        ? e.apis : e.apiCallSequence;
    const HashWorkflowEvidence hash = hashWorkflow(e.apis, calls);
    const std::string comparison = resultDecisionApi(
        e, isComparatorApiKey, /*acceptDirectReturn*/false);
    std::string verifier = resultDecisionApi(
        e, isCryptographicVerifierApiKey, /*acceptDirectReturn*/true);
    if (verifier.empty() && subject.subject == SemanticSubject::Integrity)
        verifier = resultDecisionApi(e, isTrustVerifierApiKey, /*acceptDirectReturn*/true);

    const OperationWorkflowEvidence decrypt = decryptWorkflow(e.apis, calls);
    const OperationWorkflowEvidence encrypt = encryptWorkflow(e.apis, calls);
    const std::string decompress = firstApiMatching(e.apis, isDecompressApiKey);
    const std::string generate = firstApiMatching(e.apis, isRandomGenerationApiKey);
    const bool randomSupportsHash = hash.complete && !generate.empty() &&
        (subject.subject == SemanticSubject::License ||
         subject.subject == SemanticSubject::Serial ||
         subject.subject == SemanticSubject::Password ||
         subject.subject == SemanticSubject::Credential);
    const int transformKinds = (hash.complete ? 1 : 0) + (decrypt.complete ? 1 : 0) +
                               (encrypt.complete ? 1 : 0) + (!decompress.empty() ? 1 : 0) +
                               ((!generate.empty() && !randomSupportsHash) ? 1 : 0);

    const std::string prefix = std::string("context \"") + subject.cue + "\" + ";
    auto set = [&](const char* suffix, std::string operationReason) {
        guess.name = std::string(subjectStem(subject.subject)) + suffix;
        guess.reason = prefix + std::move(operationReason);
        guess.guessed = true;
    };

    // A checked comparator/verifier is result-content evidence.  Checking the
    // status from CryptHashData is intentionally not: that only proves whether
    // the hashing API succeeded, never whether a license or password matched.
    if ((!comparison.empty() || !verifier.empty()) &&
        (supportsValidation(subject.subject) || subject.subject == SemanticSubject::Integrity) &&
        !decrypt.complete && !encrypt.complete && decompress.empty() &&
        (generate.empty() || randomSupportsHash)) {
        std::string detail;
        if (!comparison.empty())
            detail = "checked comparison result from " + comparison;
        else
            detail = "checked/returned verification result from " + verifier;
        if (hash.complete) detail += " after " + hash.detail;
        set(subject.subject == SemanticSubject::Integrity ? "Verification" : "Validation",
            std::move(detail));
        return guess;
    }

    // Narrow operation names require one unambiguous transform/generator kind.
    if (transformKinds != 1) return guess;
    if (hash.complete && supportsHashing(subject.subject)) {
        set("Hashing", hash.detail);
    } else if (decrypt.complete && subject.encryptionCue &&
               (subject.subject == SemanticSubject::Config ||
                subject.subject == SemanticSubject::Payload ||
                subject.subject == SemanticSubject::Token)) {
        set("Decryption", decrypt.detail);
    } else if (encrypt.complete && subject.encryptionCue &&
               (subject.subject == SemanticSubject::Config ||
                subject.subject == SemanticSubject::Payload ||
                subject.subject == SemanticSubject::Token)) {
        set("Encryption", encrypt.detail);
    } else if (!decompress.empty() &&
               subject.compressionCue &&
               (subject.subject == SemanticSubject::Payload ||
                subject.subject == SemanticSubject::Config)) {
        set("Decompression", "calls exact decompression API " + decompress);
    } else if (!generate.empty() && subject.subject == SemanticSubject::Token) {
        set("Generation", "calls exact random-generation API " + generate);
    }
    return guess;
}

// The semantic-classification table: map a function's set of called APIs to a
// meaningful verb. Ordered most-specific / most-telling first so a function that
// e.g. reads a file *and* memcpys gets "read_file" rather than "copy_memory".
// Returns "" when nothing recognizable is called.
std::string semanticName(const std::vector<std::string>& apis) {
    // Never infer behavior from a substring in an unknown vendor export. Keep
    // punctuation inside the API name significant, and normalize only real
    // import/calling-convention decoration. ANSI/Wide variants are admitted for
    // the Windows families explicitly listed below, not arbitrary CRT names.
    std::unordered_set<std::string> keys;
    for (const auto& api : apis) keys.insert(nameKey(undecoratedImportName(api)));
    const auto exact = [&](std::initializer_list<const char*> names) {
        for (const char* name : names) if (keys.count(name)) return true;
        return false;
    };
    const auto win = [&](std::initializer_list<const char*> names) {
        for (const char* name : names) {
            const std::string base = name;
            if (keys.count(base) || keys.count(base + "a") || keys.count(base + "w"))
                return true;
        }
        return false;
    };

    // --- code injection / process manipulation (high RE signal) ---
    if (exact({"writeprocessmemory"}) && exact({"virtualallocex", "virtualallocexnuma",
            "createremotethread", "createremotethreadex", "ntcreatethreadex", "queueuserapc"}))
        return "inject_code";
    if (exact({"createremotethread", "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread"}))
        return "inject_thread";
    if (exact({"writeprocessmemory", "ntwritevirtualmemory", "zwwritevirtualmemory"})) return "write_process_memory";
    if (exact({"readprocessmemory", "ntreadvirtualmemory", "zwreadvirtualmemory"})) return "read_process_memory";
    if (exact({"virtualallocex", "virtualallocexnuma"})) return "alloc_remote_memory";
    // Allocation/protection API names do not establish executable permissions.
    if (exact({"virtualprotect", "virtualprotectex"}) && exact({"virtualalloc", "virtualalloc2"}))
        return "allocate_protected_memory";
    if (exact({"virtualalloc", "virtualalloc2", "virtualalloc2fromapp"})) return "allocate_memory";
    if (exact({"virtualprotect", "virtualprotectex", "virtualprotectfromapp", "mprotect"})) return "change_protection";

    // --- anti-analysis / privilege / enumeration ---
    if (exact({"isdebuggerpresent", "checkremotedebuggerpresent"})) return "check_debugger";
    if (win({"process32first", "process32next"}) || exact({"enumprocesses", "k32enumprocesses"})) return "enumerate_processes";
    if (win({"module32first", "module32next"}) || exact({"enumprocessmodules", "enumprocessmodulesex", "k32enumprocessmodules", "k32enumprocessmodulesex"})) return "enumerate_modules";
    if (exact({"thread32first", "thread32next"})) return "enumerate_threads";
    if (exact({"createtoolhelp32snapshot"})) return "create_system_snapshot";
    if (exact({"adjusttokenprivileges"})) return "adjust_privileges";
    if (win({"lookupprivilegevalue", "lookupprivilegename", "lookupprivilegedisplayname"})) return "lookup_privilege";
    if (exact({"openprocesstoken", "openthreadtoken"})) return "open_access_token";

    // --- cryptography ---
    if (exact({"cryptencrypt", "bcryptencrypt", "evp_encryptupdate", "evp_encryptfinal_ex"})) return "encrypt_data";
    if (exact({"cryptdecrypt", "bcryptdecrypt", "evp_decryptupdate", "evp_decryptfinal_ex"})) return "decrypt_data";
    if (exact({"crypthashdata", "cryptcreatehash", "bcryptcreatehash", "bcrypthashdata", "bcryptfinishhash", "bcrypthash",
               "evp_digest", "evp_digestupdate", "evp_digestfinal_ex", "sha1", "sha256", "sha512", "md5"})) return "hash_data";
    if (win({"cryptacquirecontext"}) || exact({"cryptgenkey", "cryptimportkey", "bcryptopenalgorithmprovider"})) return "crypto_init";

    // --- network ---
    if (win({"urldownloadtofile"})) return "download_file";
    if (win({"internetreadfile", "internetreadfileex"}) || exact({"winhttpreaddata", "winhttpreaddataex"})) return "http_read";
    if (win({"httpsendrequest", "httpsendrequestex"}) || exact({"winhttpsendrequest"})) return "http_request";
    if (win({"internetopen", "internetopenurl", "internetconnect", "httpopenrequest"}) || exact({"winhttpopen", "winhttpopenrequest", "winhttpconnect"})) return "http_connect";
    {
        const bool snd = exact({"send", "sendto", "sendmsg", "wsasend", "wsasendto", "wsasendmsg"});
        const bool rcv = exact({"recv", "recvfrom", "recvmsg", "wsarecv", "wsarecvfrom", "wsarecvmsg", "wsarecvex"});
        if (snd && rcv) return "net_transfer";
        if (snd)        return "net_send";
        if (rcv)        return "net_recv";
        if (exact({"connect", "wsaconnect", "connectex"})) return "net_connect";
        if (win({"wsasocket"}) || exact({"socket", "wsastartup", "bind", "listen", "accept", "acceptex", "wsaaccept"}))
            return "socket_setup";
    }

    // --- registry ---
    const bool registryRead = win({"regqueryvalue", "regqueryvalueex", "reggetvalue", "regquerymultiplevalues"});
    const bool registryWrite = win({"regsetvalue", "regsetvalueex", "regsetkeyvalue"});
    if (registryRead && registryWrite) return "read_write_registry";
    if (registryWrite || win({"regcreatekey", "regcreatekeyex", "regcreatekeytransacted"})) return "write_registry";
    if (win({"regdeletekey", "regdeletekeyex", "regdeletekeytransacted", "regdeletevalue", "regdeletekeyvalue", "regdeletetree"})) return "delete_registry";
    if (registryRead || win({"regopenkey", "regopenkeyex", "regopenkeytransacted", "regenumkey", "regenumkeyex", "regenumvalue"})) return "read_registry";

    // --- process launch ---
    if (win({"createprocess", "createprocessasuser", "createprocesswithlogon", "createprocesswithtoken", "shellexecute", "shellexecuteex"}) || exact({"winexec", "system", "posix_spawn", "posix_spawnp", "execve", "execv", "execvp", "execl", "execlp", "execle"}))
        return "launch_process";

    // --- service control ---
    if (win({"createservice", "openscmanager", "startservice", "controlserviceex"}) || exact({"controlservice"}))
        return "manage_service";

    // --- filesystem ---
    const bool fileWrite = exact({"writefile", "writefileex", "writefilegather", "ntwritefile", "zwwritefile", "fwrite", "fwrite_s"});
    const bool fileRead = exact({"readfile", "readfileex", "readfilescatter", "ntreadfile", "zwreadfile", "fread", "fread_s"});
    if (fileRead && fileWrite) return "read_write_file";
    if (fileWrite) return "write_file";
    if (fileRead) return "read_file";
    // POSIX descriptors can also be sockets or pipes: the name must retain
    // that uncertainty instead of assuming every read()/write() is a file.
    const bool descriptorRead = exact({"read", "pread", "pread64", "readv", "preadv", "preadv2"});
    const bool descriptorWrite = exact({"write", "pwrite", "pwrite64", "writev", "pwritev", "pwritev2"});
    if (descriptorRead && descriptorWrite) return "read_write_descriptor";
    if (descriptorRead) return "read_descriptor";
    if (descriptorWrite) return "write_descriptor";
    if (win({"deletefile", "deletefiletransacted"}) || exact({"unlink", "unlinkat", "remove"})) return "delete_file";
    if (win({"copyfile", "copyfileex", "copyfiletransacted"}) || exact({"copyfile2"})) return "copy_file";
    if (win({"movefile", "movefileex", "movefiletransacted", "movefilewithprogress"}) || exact({"rename", "renameat", "renameat2"})) return "move_file";
    if (win({"findfirstfile", "findfirstfileex", "findfirstfiletransacted", "findnextfile"}) || exact({"readdir", "readdir64", "scandir", "scandir64"})) return "enumerate_files";
    if (win({"createfilemapping", "createfilemappingnuma", "openfilemapping"}) || exact({"mapviewoffile", "mapviewoffileex", "mmap", "mmap64"})) return "map_memory";
    if (win({"createfile", "createfiletransacted"}) || exact({"createfile2", "ntcreatefile", "ntopenfile", "zwcreatefile", "zwopenfile", "fopen", "fopen_s", "wfopen", "wfopen_s", "freopen", "open", "open64", "openat", "openat64", "creat"})) return "open_file";

    // --- synchronization / library / ui / lifecycle ---
    if (win({"createmutex", "createmutexex", "openmutex"})) return "create_mutex";
    if (win({"createevent", "createeventex"})) return "create_event";
    const bool loadLibrary = win({"loadlibrary", "loadlibraryex"}) || exact({"dlopen", "dlmopen"});
    const bool resolveProc = exact({"getprocaddress", "dlsym", "dlvsym"});
    if (loadLibrary && resolveProc) return "resolve_imports";
    if (loadLibrary) return "load_library";
    if (resolveProc) return "resolve_proc";
    if (win({"messagebox", "messageboxex", "messageboxindirect"})) return "show_message";
    if (exact({"exitprocess", "terminateprocess", "exit", "abort", "quick_exit"})) return "exit_process";
    if (win({"outputdebugstring"})) return "debug_print";
    if (win({"getenvironmentvariable"}) || exact({"getenv", "getenv_s", "secure_getenv"})) return "read_env";
    if (win({"setenvironmentvariable"}) || exact({"setenv", "putenv", "unsetenv"})) return "set_env";

    // --- weaker, generic helpers (only reached if nothing above matched) ---
    if (win({"wsprintf", "wvsprintf"}) || exact({"sprintf", "sprintf_s", "snprintf", "snprintf_s", "swprintf", "swprintf_s", "vsprintf", "vsprintf_s", "vsnprintf", "vsnprintf_s", "vswprintf", "vswprintf_s"})) return "format_string";
    if (exact({"printf", "printf_s", "fprintf", "fprintf_s", "vprintf", "vfprintf", "wprintf", "fwprintf", "puts", "fputs"})) return "print_output";
    if (win({"lstrcpy", "lstrcpyn"}) || exact({"strcpy", "strcpy_s", "strncpy", "strncpy_s", "wcscpy", "wcscpy_s", "wcsncpy", "wcsncpy_s", "strlcpy"})) return "copy_string";
    if (win({"lstrcat"}) || exact({"strcat", "strcat_s", "strncat", "strncat_s", "wcscat", "wcscat_s", "wcsncat", "wcsncat_s", "strlcat"})) return "concat_string";
    if (win({"lstrlen"}) || exact({"strlen", "strnlen", "strnlen_s", "wcslen", "wcsnlen", "wcsnlen_s"})) return "string_length";
    if (win({"lstrcmp", "lstrcmpi"}) || exact({"strcmp", "strncmp", "stricmp", "strnicmp", "strcasecmp", "strncasecmp", "wcscmp", "wcsncmp", "wcsicmp", "wcsnicmp", "memcmp", "wmemcmp"})) return "compare_buffer";
    if (exact({"memcpy", "memcpy_s", "memmove", "memmove_s", "wmemcpy", "wmemmove", "rtlmovememory", "rtlcopymemory"})) return "copy_memory";
    if (exact({"memset", "memset_s", "wmemset", "bzero", "explicit_bzero", "zeromemory", "rtlzeromemory", "rtlsecurezeromemory"})) return "fill_memory";
    if (exact({"malloc", "calloc", "realloc", "reallocarray", "heapalloc", "heaprealloc", "rtlallocateheap", "localalloc", "localrealloc", "globalalloc", "globalrealloc", "aligned_alloc", "aligned_malloc", "posix_memalign"})) return "allocate_buffer";
    // Exact `free`: substring matching misclassified FreeLibrary/VirtualFree as
    // CRT buffer releases (their thin-wrapper names are more truthful).
    if (exact({"free", "heapfree", "rtlfreeheap", "localfree", "globalfree", "aligned_free"})) return "free_buffer";
    return "";
}

// Pick the most "name-like" referenced string: a bare C identifier (often a
// __FUNCTION__ / class / symbol name embedded for logging or asserts). Prefers
// shorter, mixed-case / underscored tokens; rejects plain dictionary noise.
std::string identifierString(const std::vector<std::string>& strings) {
    std::string best; int bestScore = -1;
    for (const std::string& s : strings) {
        if (s.size() < 4 || s.size() > 40) continue;
        if (!(std::isalpha((unsigned char)s[0]) || s[0] == '_')) continue;
        bool ok = true, hasUpper = false, hasLower = false, hasUnder = false, hasDigit = false;
        for (char c : s) {
            if (!(std::isalnum((unsigned char)c) || c == '_')) { ok = false; break; }
            if (std::isupper((unsigned char)c)) hasUpper = true;
            if (std::islower((unsigned char)c)) hasLower = true;
            if (c == '_') hasUnder = true;
            if (std::isdigit((unsigned char)c)) hasDigit = true;
        }
        if (!ok) continue;
        // A short lowercase word ("error", "password", "success") is data, not
        // credible embedded symbol evidence.  Require an identifier-shaped cue.
        if (!((hasUpper && hasLower) || hasUnder || (hasUpper && hasDigit))) continue;
        if (isAnonymousSubName(s)) continue;             // don't rename A to B's placeholder
        std::string low = nameKey(s);
        if (low == "__function__" || low == "__file__" || low == "__line__") continue;
        // Score: camelCase or snake_case identifiers look like real symbol names.
        int score = 0;
        if (hasUpper && hasLower) score += 3;
        if (hasUnder) score += 2;
        if (hasDigit) score += 1;
        score += (int)(40 - s.size()) / 10;           // mild preference for shorter
        if (score > bestScore) { bestScore = score; best = s; }
    }
    return best;
}

std::string compactLower(const std::string& s) {
    std::string out; out.reserve(s.size());
    for (char c : s)
        if (!std::isspace((unsigned char)c)) out.push_back((char)std::tolower((unsigned char)c));
    return out;
}

bool isFrameNoise(const Instruction& in, bool sawRet) {
    const std::string m = nameKey(in.mnemonic);
    const std::string o = compactLower(in.operands);
    if (m == "nop" || m == "endbr64" || m == "endbr32" || m == "leave") return true;
    // INT3 is common alignment after a completed body, but before the first RET
    // it is an observable trap and must not turn "int3; ret" into nullsub.
    if (sawRet && m == "int3") return true;
    if ((m == "push" || m == "pop") && (o == "rbp" || o == "ebp")) return true;
    if (m == "mov" && (o == "rbp,rsp" || o == "ebp,esp")) return true;
    return false;
}

bool zeroLiteral(std::string s) {
    while (!s.empty() && (s.front() == '#' || s.front() == '$')) s.erase(s.begin());
    if (s.size() >= 2 && s[0] == '0' && s[1] == 'x') s.erase(0, 2);
    if (!s.empty() && s.back() == 'h') s.pop_back();
    if (s.empty()) return false;
    for (char c : s) if (c != '0') return false;
    return true;
}

bool isConditionalBranch(const Instruction& in) {
    if (in.flow.kind != FlowKind::None)
        return in.flow.kind == FlowKind::ConditionalBranch;
    if (!in.isBranch || in.isCall || in.isRet) return false;
    const std::string m = nameKey(in.mnemonic);
    if (m.size() >= 2 && m[0] == 'j' && m != "jmp" && m != "jmpf") return true;
    return m == "beq" || m == "bne" || m == "b.eq" || m == "b.ne" ||
           m == "cbz" || m == "cbnz";
}

// Only equality/inequality branches consume the Boolean zero test. TEST also
// clears CF/OF and computes parity/sign, so accepting JC/JO/JP would turn a
// constant or unrelated flag decision into false online-state evidence.
bool isZeroEqualityBranch(const Instruction& in) {
    if (!isConditionalBranch(in)) return false;
    const std::string m = nameKey(in.mnemonic);
    return m == "je" || m == "jz" || m == "jne" || m == "jnz" ||
           m == "beq" || m == "bne" || m == "b.eq" || m == "b.ne";
}

std::vector<std::string> compactOperands(const Instruction& in) {
    std::vector<std::string> result;
    const std::string text = compactLower(in.operands);
    size_t start = 0;
    while (start <= text.size()) {
        const size_t comma = text.find(',', start);
        result.push_back(text.substr(start, comma == std::string::npos
            ? std::string::npos : comma - start));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return result;
}

bool isAbiAccumulator(const std::string& value) {
    // Imported BOOL/int/status APIs return at least 32 bits. A low-byte test
    // can report zero when the full return is nonzero (for example 0x100).
    return value == "eax" || value == "rax" ||
           value == "r0" || value == "w0" || value == "x0" ||
           value == "v0" || value == "$v0" || value == "$2" ||
           value == "r3" || value == "a0" || value == "x10";
}

bool isDirectBranchAccumulator(const std::string& value) {
    return value == "v0" || value == "$v0" || value == "$2" ||
           value == "a0" || value == "x10";
}

bool isNamedZeroRegister(const std::string& value) {
    return value == "zero" || value == "$zero";
}

bool branchTestsAccumulatorForZero(const Instruction& in) {
    const std::string m = nameKey(in.mnemonic);
    const auto operands = compactOperands(in);
    if ((m == "cbz" || m == "cbnz") && !operands.empty())
        return operands[0] == "r0" || operands[0] == "w0" || operands[0] == "x0";
    // MIPS and RISC-V encode the zero comparison in BEQ/BNE itself.
    if ((m == "beq" || m == "bne") && operands.size() >= 2)
        return (isDirectBranchAccumulator(operands[0]) && isNamedZeroRegister(operands[1])) ||
               (isNamedZeroRegister(operands[0]) && isDirectBranchAccumulator(operands[1]));
    return false;
}

// Canonical zero comparisons for the supported native ABIs. Restricting this to
// the ABI return register avoids mistaking an unrelated branch for result flow.
bool testsAccumulatorForZero(const Instruction& in) {
    const std::string m = nameKey(in.mnemonic);
    const auto operands = compactOperands(in);
    if (operands.size() < 2) return false;
    if (m == "test") return isAbiAccumulator(operands[0]) && operands[0] == operands[1];
    if (m == "cmp")
        return (isAbiAccumulator(operands[0]) && zeroLiteral(operands[1])) ||
               (zeroLiteral(operands[0]) && isAbiAccumulator(operands[1]));
    // PowerPC optionally prefixes the comparison with a CR field operand.
    if (m == "cmpwi" || m == "cmplwi" || m == "cmpdi" || m == "cmpldi") {
        const std::string& value = operands[operands.size() - 2];
        const std::string& zero = operands.back();
        return value == "r3" && zeroLiteral(zero);
    }
    return false;
}

// BOOL normalization is an x86-specific full-accumulator pattern.  Do not let
// a low-byte TEST feed it: SETcc writes only AL, and returning that partial EAX
// without the following MOVZX is not a valid normalized Win32 BOOL result.
bool testsFullX86AccumulatorForZero(const Instruction& in) {
    const std::string m = nameKey(in.mnemonic);
    const std::string o = compactLower(in.operands);
    const size_t comma = o.find(',');
    if (comma == std::string::npos) return false;
    const std::string a = o.substr(0, comma);
    const std::string b = o.substr(comma + 1);
    auto accumulator = [](const std::string& value) {
        return value == "eax" || value == "rax";
    };
    if (m == "test") return accumulator(a) && a == b;
    if (m == "cmp")
        return (accumulator(a) && zeroLiteral(b)) ||
               (zeroLiteral(a) && accumulator(b));
    return false;
}

bool setsZeroEqualityIntoAl(const Instruction& in) {
    const std::string m = nameKey(in.mnemonic);
    if (m != "sete" && m != "setz" && m != "setne" && m != "setnz") return false;
    return compactLower(in.operands) == "al";
}

bool zeroExtendsAlIntoEax(const Instruction& in) {
    return nameKey(in.mnemonic) == "movzx" && compactLower(in.operands) == "eax,al";
}

bool setsZeroEqualityIntoAarch64Accumulator(const Instruction& in) {
    if (nameKey(in.mnemonic) != "cset") return false;
    const auto operands = compactOperands(in);
    if (operands.size() != 2 || (operands[0] != "w0" && operands[0] != "x0"))
        return false;
    return operands[1] == "eq" || operands[1] == "ne";
}

bool normalizesAccumulatorDirectly(const Instruction& in) {
    const std::string m = nameKey(in.mnemonic);
    if (m != "seqz" && m != "snez") return false;
    const auto operands = compactOperands(in);
    return operands.size() == 2 && isDirectBranchAccumulator(operands[0]) &&
           operands[0] == operands[1];
}

// A direct BOOL-return wrapper commonly tears down its ABI frame between the
// imported call and RET.  These operations leave EAX intact; no other work is
// allowed in the direct-return pattern.
bool isReturnValueTransparentFrameOp(const Instruction& in) {
    if (isFrameNoise(in, false)) return true;
    const std::string m = nameKey(in.mnemonic);
    const std::string o = compactLower(in.operands);
    const size_t comma = o.find(',');
    const std::string dst = o.substr(0, comma);
    if (m == "add" && (dst == "rsp" || dst == "esp")) return true;
    if (m == "mov" && (o == "rsp,rbp" || o == "esp,ebp")) return true;
    if (m == "pop" && (o == "rbx" || o == "ebx" || o == "rcx" || o == "ecx" ||
        o == "rdx" || o == "edx" || o == "rsi" || o == "esi" || o == "rdi" || o == "edi" ||
        o == "r8" || o == "r9" || o == "r10" || o == "r11" || o == "r12" ||
        o == "r13" || o == "r14" || o == "r15")) return true;
    return m == "lea" && (dst == "rsp" || dst == "esp");
}

bool zeroesAccumulator(const Instruction& in) {
    const std::string m = nameKey(in.mnemonic);
    const std::string o = compactLower(in.operands);
    if ((m == "xor" || m == "sub") && (o == "eax,eax" || o == "rax,rax")) return true;
    if (m != "mov") return false;
    size_t comma = o.find(',');
    if (comma == std::string::npos) return false;
    const std::string dst = o.substr(0, comma);
    return (dst == "eax" || dst == "rax") && zeroLiteral(o.substr(comma + 1));
}

// Conservative x86 accumulator-clobber tracking for ret_zero.  False negatives
// are preferable to claiming "returns 0" after a later write made that untrue.
bool writesAccumulator(const Instruction& in) {
    const auto accumulator = [](const std::string& reg) {
        return reg == "rax" || reg == "eax" || reg == "ax" || reg == "al" || reg == "ah";
    };
    for (const auto& operand : in.typedOperands)
        if (operand.kind == OperandKind::Register && OperandWrites(operand.access) &&
            accumulator(nameKey(operand.registerName))) return true;
    for (const auto& reg : in.registersWritten)
        if (accumulator(nameKey(reg))) return true;
    const std::string m = nameKey(in.mnemonic);
    const std::string o = compactLower(in.operands);
    size_t comma = o.find(',');
    const std::string dst = o.substr(0, comma);
    const bool explicitAcc = accumulator(dst);
    if (explicitAcc && m != "cmp" && m != "test" && m != "bt" && m != "push") return true;
    if ((m == "xchg" || m == "xadd") && comma != std::string::npos &&
        accumulator(o.substr(comma + 1))) return true;
    return m == "mul" || (m == "imul" && comma == std::string::npos) ||
           m == "div" || m == "idiv" ||
           m == "cpuid" || m == "rdtsc" || m == "rdtscp" || m == "xgetbv" ||
           m == "cmpxchg" || m == "cmpxchg8b" || m == "cmpxchg16b" ||
           m == "syscall" || m == "sysenter" || m == "lahf" || m == "popad" ||
           m.rfind("lods", 0) == 0;
}

// Small typed leaf recognizer. This deliberately accepts only copies, exact
// zero/one tests, equality SETcc/Jcc, and balanced frame mechanics. Every path
// must finish, and unknown operations/calls/loops invalidate the whole result.
// A general function containing a flag check is not itself named a predicate.
std::string scalarRegisterFamily(const std::string& raw) {
    const std::string reg = nameKey(raw);
    if (reg == "rax" || reg == "eax" || reg == "ax" || reg == "al") return "rax";
    if (reg == "rcx" || reg == "ecx" || reg == "cx" || reg == "cl") return "rcx";
    if (reg == "rdx" || reg == "edx" || reg == "dx" || reg == "dl") return "rdx";
    if (reg == "rbx" || reg == "ebx" || reg == "bx" || reg == "bl") return "rbx";
    if (reg == "rsi" || reg == "esi" || reg == "si" || reg == "sil") return "rsi";
    if (reg == "rdi" || reg == "edi" || reg == "di" || reg == "dil") return "rdi";
    if (reg == "rbp" || reg == "ebp" || reg == "bp" || reg == "bpl") return "rbp";
    if (reg == "rsp" || reg == "esp" || reg == "sp" || reg == "spl") return "rsp";
    for (int i = 8; i <= 15; ++i) {
        const std::string base = "r" + std::to_string(i);
        if (reg == base || reg == base + "d" || reg == base + "w" || reg == base + "b")
            return base;
    }
    return {};
}

struct ScalarValue {
    enum class Kind { Unknown, Constant, Source, Predicate } kind = Kind::Unknown;
    ScalarFunctionEvidence source;
    uint64_t constant = 0; // comparison literal for Predicate
    uint16_t width = 0; // actually defined register width, independent of source
    bool unequal = false;
};

bool sameScalarSource(const ScalarValue& a, const ScalarValue& b) {
    return a.source.sourceDescription == b.source.sourceDescription &&
           a.source.widthBits == b.source.widthBits;
}

ScalarFunctionEvidence scalarLeafEvidence(const std::vector<Instruction>& body,
                                           bool x64) {
    if (body.empty() || body.size() > 24) return {};
    std::unordered_map<uint64_t, size_t> at;
    for (size_t i = 0; i < body.size(); ++i) {
        if (!at.emplace(body[i].address, i).second || body[i].flow.delaySlots ||
            !body[i].prefixes.empty() || body[i].isRepString ||
            InstructionIsCall(body[i]) || !body[i].extraTargets.empty() ||
            !body[i].switchInfo.cases.empty() || body[i].switchInfo.defaultTargetValid)
            return {};
    }
    struct Path {
        size_t index = 0;
        std::unordered_map<std::string, ScalarValue> registers;
        ScalarValue flags, condition;
        ScalarFunctionEvidence store;
        std::unordered_set<size_t> visited;
        int memoryReads = 0;
        int frame = 0; // 0 absent/restored, 1 pushed, 2 frame pointer established
        bool branched = false;
    };
    struct Returned { ScalarValue value, condition; ScalarFunctionEvidence store; };
    std::vector<Path> pending(1);
    std::vector<Returned> returns;
    while (!pending.empty()) {
        Path path = std::move(pending.back()); pending.pop_back();
        for (;;) {
            if (path.index >= body.size() || !path.visited.insert(path.index).second)
                return {}; // falling out of the body or a cycle is not a leaf proof
            const Instruction& in = body[path.index];
            const std::string m = nameKey(in.mnemonic);
            const auto& operands = in.typedOperands;
            const auto next = [&]() -> bool {
                if (in.address > (std::numeric_limits<uint64_t>::max)() - in.length) return false;
                const auto found = at.find(in.address + in.length);
                if (found == at.end()) return false;
                path.index = found->second;
                return true;
            };
            const auto memorySource = [&](const TypedOperand& operand) -> ScalarFunctionEvidence {
                if (operand.kind != OperandKind::Memory ||
                    (operand.widthBits != 8 && operand.widthBits != 16 &&
                     operand.widthBits != 32 && operand.widthBits != 64) ||
                    !operand.indexRegister.empty()) return {};
                const std::string segment = nameKey(operand.segmentRegister);
                if (!segment.empty() && segment != "ds" && segment != "ss") return {};
                ScalarFunctionEvidence source;
                source.widthBits = operand.widthBits;
                source.instructionVA = in.address;
                uint64_t address = 0;
                const std::string base = nameKey(operand.baseRegister);
                if (base.empty() || base == "rip" || base == "eip") {
                    if (!TryGetInstrDataRef(in, address)) return {};
                    char text[48];
                    std::snprintf(text, sizeof(text), "%llx", static_cast<unsigned long long>(address));
                    source.sourceIdentifier = std::string("global_") + text;
                    source.sourceDescription = std::string("[0x") + text + "]";
                } else {
                    const std::string family = scalarRegisterFamily(base);
                    if (family.empty() || family == "rsp" || family == "rbp" ||
                        path.registers.count(family) || operand.pcRelative ||
                        (operand.displacement != 0 && !operand.displacementValid)) return {};
                    const int64_t displacement = operand.displacement;
                    // Negating INT64_MIN in signed arithmetic is undefined.
                    const uint64_t magnitude = displacement < 0
                        ? uint64_t(0) - static_cast<uint64_t>(displacement)
                        : static_cast<uint64_t>(displacement);
                    char text[48];
                    std::snprintf(text, sizeof(text), "%llx", static_cast<unsigned long long>(magnitude));
                    source.sourceIdentifier = std::string("field_") + (displacement < 0 ? "minus_" : "") + text;
                    source.sourceDescription = "[" + base;
                    if (displacement) source.sourceDescription += std::string(displacement < 0 ? "-0x" : "+0x") + text;
                    source.sourceDescription += "]";
                }
                return source;
            };
            const auto read = [&](const TypedOperand& operand) -> ScalarValue {
                ScalarValue value;
                if (!OperandReads(operand.access)) return value;
                value.width = operand.widthBits;
                if (operand.kind == OperandKind::Immediate && !operand.pcRelative) {
                    value.kind = ScalarValue::Kind::Constant; value.constant = operand.immediate;
                } else if (operand.kind == OperandKind::Memory) {
                    if (++path.memoryReads > 1 || path.store.kind != ScalarFunctionKind::None) return {};
                    value.source = memorySource(operand);
                    if (value.source.sourceIdentifier.empty()) return {};
                    value.kind = ScalarValue::Kind::Source;
                } else if (operand.kind == OperandKind::Register &&
                           (operand.widthBits == 8 || operand.widthBits == 16 ||
                            operand.widthBits == 32 || operand.widthBits == 64)) {
                    const std::string family = scalarRegisterFamily(operand.registerName);
                    if (family.empty() || family == "rsp" || family == "rbp") return {};
                    if (const auto found = path.registers.find(family); found != path.registers.end()) {
                        value = found->second;
                        if (value.width != operand.widthBits) {
                            // Known 0/1 values can be narrowed safely; a loaded
                            // scalar cannot silently become a low-byte test.
                            if (value.width < operand.widthBits ||
                                (value.kind != ScalarValue::Kind::Predicate &&
                                 !(value.kind == ScalarValue::Kind::Constant && value.constant <= 1))) return {};
                            value.width = operand.widthBits;
                        }
                    } else {
                        value.kind = ScalarValue::Kind::Source;
                        value.source.sourceIdentifier = nameKey(operand.registerName);
                        value.source.sourceDescription = value.source.sourceIdentifier;
                        value.source.widthBits = operand.widthBits;
                        value.source.instructionVA = in.address;
                    }
                }
                return value;
            };
            const auto write = [&](const TypedOperand& operand, ScalarValue value) -> bool {
                if (value.kind == ScalarValue::Kind::Unknown || operand.kind != OperandKind::Register ||
                    !OperandWrites(operand.access)) return false;
                const std::string family = scalarRegisterFamily(operand.registerName);
                if (family != "rax" && family != "rcx" && family != "rdx" &&
                    !(x64 && (family == "r8" || family == "r9" || family == "r10" || family == "r11")))
                    return false; // no unbalanced callee-saved register writes
                if (operand.widthBits != 8 && operand.widthBits != 16 &&
                    operand.widthBits != 32 && operand.widthBits != 64) return false;
                value.width = operand.widthBits;
                if (operand.widthBits == 8 || operand.widthBits == 16) {
                    const auto old = path.registers.find(family);
                    if (old != path.registers.end() && old->second.width >= 32 &&
                        old->second.kind == ScalarValue::Kind::Constant && old->second.constant == 0 &&
                        (value.kind == ScalarValue::Kind::Predicate ||
                         (value.kind == ScalarValue::Kind::Constant && value.constant <= 1)))
                        value.width = old->second.width;
                }
                path.registers[family] = std::move(value);
                return true;
            };
            if (InstructionIsReturn(in)) {
                if (m != "ret" || path.frame != 0) return {};
                ScalarValue result;
                if (const auto found = path.registers.find("rax"); found != path.registers.end() &&
                    found->second.width >= 32) result = found->second;
                returns.push_back({result, path.condition, path.store});
                if (returns.size() > 2) return {};
                break;
            }
            if (isConditionalBranch(in)) {
                if (!isZeroEqualityBranch(in) || m[0] != 'j' || path.branched ||
                    path.flags.kind != ScalarValue::Kind::Predicate ||
                    path.store.kind != ScalarFunctionKind::None) return {};
                uint64_t target = 0;
                if (!TryGetDirectTarget(in, target) || !at.count(target)) return {};
                path.branched = true;
                path.condition = path.flags;
                path.condition.unequal = m == "jne" || m == "jnz";
                Path taken = path; taken.index = at.at(target);
                pending.push_back(std::move(taken));
                path.condition.unequal = !path.condition.unequal;
                path.flags = {};
                if (!next()) return {};
                continue;
            }
            if (InstructionEndsBlock(in)) {
                uint64_t target = 0;
                if (m != "jmp" || !TryGetDirectTarget(in, target) || !at.count(target)) return {};
                path.index = at.at(target); continue;
            }
            if (m == "nop" || m == "endbr64" || m == "endbr32") {
                if (!next()) return {};
                continue;
            }
            const std::string text = compactLower(in.operands);
            if (m == "push" && (text == "rbp" || text == "ebp") && path.frame == 0 &&
                path.registers.empty() && path.memoryReads == 0 && !path.branched) {
                path.frame = 1;
            } else if (m == "mov" && (text == "rbp,rsp" || text == "ebp,esp") && path.frame == 1) {
                path.frame = 2;
            } else if ((m == "pop" && (text == "rbp" || text == "ebp") && path.frame != 0) ||
                       (m == "leave" && path.frame == 2)) {
                path.frame = 0;
            } else if (m == "mov" || m == "movzx") {
                if (operands.size() != 2) return {};
                ScalarValue value = read(operands[1]);
                if (operands[0].kind == OperandKind::Memory) {
                    if (m != "mov" || !OperandWrites(operands[0].access) ||
                        path.memoryReads || path.branched || path.store.kind != ScalarFunctionKind::None ||
                        value.kind != ScalarValue::Kind::Constant || value.constant > 1) return {};
                    path.store = memorySource(operands[0]);
                    if (path.store.sourceIdentifier.empty()) return {};
                    path.store.kind = value.constant ? ScalarFunctionKind::SetOne : ScalarFunctionKind::SetZero;
                } else {
                    if ((m == "mov" && operands[1].kind != OperandKind::Immediate &&
                         operands[0].widthBits != operands[1].widthBits) ||
                        (m == "movzx" && (operands[1].kind == OperandKind::Immediate ||
                         operands[0].widthBits <= operands[1].widthBits)) ||
                        !write(operands[0], std::move(value))) return {};
                }
            } else if (m == "xor" && operands.size() == 2 &&
                       operands[0].kind == OperandKind::Register &&
                       operands[1].kind == OperandKind::Register &&
                       operands[0].registerName == operands[1].registerName &&
                       operands[0].widthBits == operands[1].widthBits) {
                ScalarValue zero; zero.kind = ScalarValue::Kind::Constant;
                if (!write(operands[0], zero)) return {};
                path.flags = {}; // a later SETcc must not use the prior CMP
            } else if ((m == "cmp" || m == "test") && operands.size() == 2) {
                if (path.store.kind != ScalarFunctionKind::None) return {};
                ScalarValue source = read(operands[0]);
                uint64_t literal = 0;
                if (m == "test") {
                    if (operands[0].kind != OperandKind::Register ||
                        operands[1].kind != OperandKind::Register ||
                        operands[0].registerName != operands[1].registerName ||
                        operands[0].widthBits != operands[1].widthBits) return {};
                } else {
                    if (operands[1].kind != OperandKind::Immediate || operands[1].pcRelative ||
                        operands[1].immediate > 1 || !OperandReads(operands[1].access)) return {};
                    literal = operands[1].immediate;
                }
                if (source.kind != ScalarValue::Kind::Source) return {};
                source.kind = ScalarValue::Kind::Predicate;
                source.constant = literal; source.unequal = false;
                path.flags = std::move(source);
            } else if (m == "sete" || m == "setz" || m == "setne" || m == "setnz") {
                if (operands.size() != 1 || operands[0].widthBits != 8 ||
                    path.flags.kind != ScalarValue::Kind::Predicate) return {};
                ScalarValue value = path.flags;
                value.unequal = m == "setne" || m == "setnz";
                if (!write(operands[0], value)) return {};
            } else return {};
            if (!next()) return {};
        }
    }
    if (returns.empty()) return {};
    if (returns.size() == 1 && returns[0].store.kind != ScalarFunctionKind::None) {
        auto evidence = returns[0].store; evidence.complete = true; return evidence;
    }
    ScalarValue result = returns[0].value;
    if (returns.size() == 2) {
        const auto& first = returns[0]; const auto& second = returns[1];
        if (first.store.kind != ScalarFunctionKind::None || second.store.kind != ScalarFunctionKind::None ||
            first.value.kind != ScalarValue::Kind::Constant || second.value.kind != ScalarValue::Kind::Constant ||
            first.value.constant > 1 || second.value.constant > 1 ||
            first.value.constant == second.value.constant ||
            first.condition.kind != ScalarValue::Kind::Predicate ||
            second.condition.kind != ScalarValue::Kind::Predicate ||
            !sameScalarSource(first.condition, second.condition) ||
            first.condition.constant != second.condition.constant ||
            first.condition.unequal == second.condition.unequal) return {};
        result = first.condition;
        if (!first.value.constant) result.unequal = !result.unequal;
    }
    ScalarFunctionEvidence evidence = result.source;
    if (result.kind == ScalarValue::Kind::Predicate) {
        evidence.kind = result.constant == 0
            ? (result.unequal ? ScalarFunctionKind::IsNonzero : ScalarFunctionKind::IsZero)
            : (result.unequal ? ScalarFunctionKind::IsNotOne : ScalarFunctionKind::IsOne);
    } else if (result.kind == ScalarValue::Kind::Source &&
               evidence.sourceDescription.find('[') != std::string::npos) {
        evidence.kind = ScalarFunctionKind::Getter;
    } else return {};
    evidence.complete = true;
    return evidence;
}

} // namespace

std::string ToSnakeIdentifier(const std::string& api) {
    std::string a = undecoratedImportName(api);
    if (a.empty() || a[0] == '?') return {};
    // Drop a trailing ANSI/Wide variant suffix ("CreateFileW" -> "CreateFile").
    if (a.size() >= 2 && (a.back() == 'A' || a.back() == 'W') &&
        std::islower((unsigned char)a[a.size() - 2]))
        a.pop_back();

    std::string out;
    for (size_t k = 0; k < a.size(); ++k) {
        char c = a[k];
        if (c == '@' || c == '?' || c == '$') break;             // decorated tail
        bool up = std::isupper((unsigned char)c) != 0;
        bool prevAlnumLower = k > 0 && (std::islower((unsigned char)a[k - 1]) ||
                                        std::isdigit((unsigned char)a[k - 1]));
        bool nextLower = k + 1 < a.size() && std::islower((unsigned char)a[k + 1]);
        if (up && !out.empty() && out.back() != '_' && (prevAlnumLower || nextLower))
            out.push_back('_');
        if (std::isalnum((unsigned char)c)) out.push_back((char)std::tolower((unsigned char)c));
        else if (!out.empty() && out.back() != '_') out.push_back('_');
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    size_t b = 0; while (b < out.size() && out[b] == '_') ++b;
    out = out.substr(b);
    if (out.empty()) return {};
    if (std::isdigit((unsigned char)out[0])) out = "fn_" + out;
    return out;
}

GuessedName GuessFromEvidence(const FuncEvidence& e) {
    GuessedName g;
    auto set = [&](std::string name, std::string reason) {
        g.name = std::move(name); g.reason = std::move(reason); g.guessed = true;
    };

    // 1) Authoritative initial analysis root. A raw base is deliberately not
    // described as an image entry point: flat blobs have no such header field.
    if (e.isRawStart) { set("start", "analyst-selected raw image base"); return g; }
    if (e.isEntry) { set("start", "image entry point"); return g; }

    // 2) Thunk / wrapper that tail-jumps straight to a known import.
    if (e.isThunk && !e.thunkApi.empty()) {
        if (std::string api = thunkIdentifier(e.thunkApi); !api.empty()) {
            set("j_" + api, "tail-jumps to " + e.thunkApi);
            return g;
        }
    }

    // 3) Trivial stubs.
    if (!e.bodySampled && e.retOnly && e.callCount == 0) { set("nullsub", "empty stub (returns immediately)"); return g; }
    if (!e.bodySampled && e.retZero && e.callCount == 0) { set("ret_zero", "returns 0"); return g; }

    // 4) Subject + operation synthesis.  This is more specific than the generic
    // API-set verbs below, but it is allowed only when two independent evidence
    // kinds agree and the function remains within conservative complexity bounds.
    if (GuessedName contextual = contextualSemanticGuess(e); contextual.guessed)
        return contextual;

    // 5) A dedicated connectivity predicate whose Boolean result is itself
    // checked/returned.  The API alone is insufficient: it may be one small
    // part of a larger worker.  A dedicated check may combine multiple exact
    // connectivity predicates, but any other imported behavior is a veto.
    if (!e.apis.empty()) {
        const std::string connectivityApi = connectivityPredicateIn(e.apis);
        const bool predicateUse = e.connectivityResultChecked ||
                                  e.connectivityResultReturned;
        constexpr int kMaxConnectivityInstructions = 96;
        constexpr int kMaxConnectivityCalls = 4;
        if (!e.bodySampled && !connectivityApi.empty() && predicateUse &&
            e.instrCount > 0 && e.callCount > 0 &&
            e.instrCount <= kMaxConnectivityInstructions &&
            e.callCount <= kMaxConnectivityCalls &&
            hasOnlyConnectivityPredicateApis(e.apis) &&
            !hasTransportOrPayloadApi(e.apis)) {
            std::string reason;
            if (e.connectivityResultChecked)
                reason = "branches on " + connectivityApi + " connectivity result";
            else
                reason = "returns " + connectivityApi + " connectivity result directly";
            reason += "; no non-predicate API calls observed";
            set("WifiCheck", std::move(reason));
            return g;
        }

        // 6) Semantic name from the set of imported APIs it calls.
        std::string s = semanticName(e.apis);
        if (!s.empty()) {
            std::string r = "calls " + joinApis(e.apis);
            if (e.selfRecursive) r += "; recursive";
            set(std::move(s), std::move(r));
            return g;
        }
        // 7) Thin wrapper around exactly one notable API.
        if (!e.bodySampled && e.apis.size() == 1 && e.callCount <= 2 && e.instrCount <= 24) {
            if (std::string name = ToSnakeIdentifier(e.apis[0]); !name.empty()) {
                set(std::move(name), "wrapper around " + e.apis[0]);
                return g;
            }
        }
    }

    // 8) A distinctive identifier-like referenced string (embedded symbol name).
    if (std::string id = identifierString(e.strings); !id.empty()) {
        set(id, "references \"" + id + "\"");
        return g;
    }

    // 9) An affirmative action message corroborated by a typed, non-stack
    // stored operation in the same short basic block. Keep all stronger naming
    // evidence above; message semantics remain explicitly a candidate.
    if (!e.bodySampled && e.instrCount > 0 && e.instrCount <= 192 && e.callCount <= 8) {
        std::string agreedName, reason;
        bool conflict = false;
        for (const auto& action : e.stringActions) {
            if (!action.sameBlock || action.storedAddition == action.storedSubtraction) continue;
            const std::string name = StringActionSuggestedName(action.text,
                action.storedAddition ? StringActionKind::Add : StringActionKind::Subtract);
            if (name.empty()) continue;
            if (!agreedName.empty() && agreedName != name) { conflict = true; break; }
            agreedName = name;
            char location[112];
            std::snprintf(location, sizeof(location), " at 0x%llX; string reference at 0x%llX",
                static_cast<unsigned long long>(action.instructionVA),
                static_cast<unsigned long long>(action.stringRefVA));
            reason = "candidate from \"" + action.text.substr(0, 160) + "\" and typed stored " +
                (action.storedAddition ? "addition" : "subtraction") + location +
                "; same basic block; field meaning and execution remain unproved";
        }
        if (!conflict && !agreedName.empty()) { set(std::move(agreedName), std::move(reason)); return g; }
    }

    // 10) Typed leaf semantics supply useful names even in fully stripped
    // code. No adjacent strings or bare 0/1 constants supply a game/domain label.
    const auto& scalar = e.scalarFunction;
    if (!e.bodySampled && e.callCount == 0 && e.instrCount > 0 && e.instrCount <= 24 &&
        scalar.complete && isIdentifier(scalar.sourceIdentifier) &&
        !scalar.sourceDescription.empty() &&
        (scalar.widthBits == 8 || scalar.widthBits == 16 || scalar.widthBits == 32 || scalar.widthBits == 64)) {
        std::string name, reason;
        const std::string source = std::to_string(scalar.widthBits) + "-bit " + scalar.sourceDescription;
        switch (scalar.kind) {
        case ScalarFunctionKind::Getter:
            name = "read_" + scalar.sourceIdentifier;
            reason = "returns the value read from " + source;
            break;
        case ScalarFunctionKind::SetZero:
        case ScalarFunctionKind::SetOne: {
            const bool one = scalar.kind == ScalarFunctionKind::SetOne;
            name = "write_" + scalar.sourceIdentifier + (one ? "_one" : "_zero");
            reason = std::string("writes ") + (one ? "1" : "0") + " to " + source;
            break;
        }
        case ScalarFunctionKind::IsZero:
        case ScalarFunctionKind::IsNonzero:
        case ScalarFunctionKind::IsOne:
        case ScalarFunctionKind::IsNotOne: {
            const bool one = scalar.kind == ScalarFunctionKind::IsOne || scalar.kind == ScalarFunctionKind::IsNotOne;
            const bool unequal = scalar.kind == ScalarFunctionKind::IsNonzero || scalar.kind == ScalarFunctionKind::IsNotOne;
            name = "is_" + scalar.sourceIdentifier + (one ? (unequal ? "_not_one" : "_one") : (unequal ? "_nonzero" : "_zero"));
            reason = "returns 1 exactly when " + source + (unequal ? " != " : " == ") + (one ? "1" : "0") + "; returns 0 otherwise";
            break;
        }
        default: break;
        }
        if (!name.empty()) {
            char location[48];
            std::snprintf(location, sizeof(location), "0x%llX", static_cast<unsigned long long>(scalar.instructionVA));
            set(std::move(name), reason + "; typed source at " + location +
                "; complete leaf body; application meaning remains unknown");
            return g;
        }
    }

    return g;   // no confident guess; caller keeps sub_<addr>
}

// ----------------------------------------------------------------- the pass ---

std::vector<GuessedName>
FunctionNamer::name(const BinaryFile& bin, IDisassembler& dis,
                    const std::vector<NamerInput>& funcs, uint64_t entryVA,
                    const std::function<std::string(uint64_t)>& importNameFor,
                    const std::function<std::string(uint64_t)>& stringRefFor,
                    const std::function<bool()>& cancelled) {
    return name(bin, dis, funcs, entryVA, entryVA != 0, false,
                importNameFor, stringRefFor, cancelled);
}

std::vector<GuessedName>
FunctionNamer::name(const BinaryFile& bin, IDisassembler& dis,
                    const std::vector<NamerInput>& funcs, uint64_t startVA,
                    bool startValid, bool rawAnalysisStart,
                    const std::function<std::string(uint64_t)>& importNameFor,
                    const std::function<std::string(uint64_t)>& stringRefFor,
                    const std::function<bool()>& cancelled) {
    guessed_ = 0;
    const auto stopped = [&] {
        if (!cancelled || !cancelled()) return false;
        guessed_ = 0;
        return true;
    };
    if (stopped()) return {};
    std::vector<GuessedName> out(funcs.size());

    auto isGuessable = [](const NamerInput& f) {
        return !f.isExport && isAnonymousSubName(f.name);
    };

    // Resolve a call/jmp instruction's target to an import name (direct target or
    // an IAT slot referenced through memory). "" when it isn't an import.
    auto resolveTargetApi = [&](const Instruction& in) -> std::string {
        std::string nm;
        uint64_t target = 0;
        if (TryGetDirectTarget(in, target) && importNameFor) nm = importNameFor(target);
        if (nm.empty()) {
            uint64_t mem = 0;
            if (TryGetInstrDataRef(in, mem) && importNameFor)    // call/jmp [iat]
                nm = importNameFor(mem);
        }
        return nm;
    };

    // The thunk pass needs only the first non-padding instruction. Retaining
    // 512 rich Instructions for every function can exhaust memory on a large
    // image, so probe the prefix, then stream full bodies during synthesis.
    std::vector<uint64_t> functionStarts;
    functionStarts.reserve(funcs.size());
    for (const auto& function : funcs) {
        if (stopped()) return {};
        functionStarts.push_back(function.address);
    }
    std::sort(functionStarts.begin(), functionStarts.end());
    auto bodyBytes = [&](const NamerInput& f, size_t& win) {
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(f.address, avail);
        win = f.size ? std::min<size_t>(avail, f.size) : std::min<size_t>(avail, 2048);
        win = std::min<size_t>(win, 8192);
        const auto next = std::upper_bound(functionStarts.begin(), functionStarts.end(), f.address);
        if (next != functionStarts.end())
            win = static_cast<size_t>(std::min<uint64_t>(win, *next - f.address));
        return p;
    };

    // ---- Pass 1: detect thunks so calls *to* a thunk resolve to its API. ----
    struct ThunkInfo {
        bool isThunk = false;
        bool targetValid = false;
        bool resolved = false;
        std::string api;
        uint64_t target = 0;
    };
    std::unordered_map<uint64_t, ThunkInfo> thunks;
    for (size_t i = 0; i < funcs.size(); ++i) {
        if (stopped()) return {};
        size_t win = 0;
        const uint8_t* p = bodyBytes(funcs[i], win);
        if (!p) continue;
        ThunkInfo t;
        size_t offset = 0;
        for (size_t count = 0; offset < win && count < 512; ++count) {
            if ((count & 0x3Fu) == 0 && stopped()) return {};
            Instruction in;
            if (!dis.decodeOne(p + offset, win - offset, funcs[i].address + offset, in) ||
                !in.length || in.length > win - offset) break;
            offset += in.length;
            if (in.mnemonic == "endbr64" || in.mnemonic == "endbr32" || in.mnemonic == "nop")
                continue;                                        // skip CET/padding prologue
            if (in.mnemonic == "jmp") {                          // unconditional -> tail call
                t.isThunk = true;
                t.api    = bareApi(resolveTargetApi(in));
                t.targetValid = TryGetDirectTarget(in, t.target);
            }
            break;                                               // only the first real instruction matters
        }
        if (t.isThunk) thunks[funcs[i].address] = t;
    }

    // Follow each one-successor chain once, memoizing both resolved imports and
    // dead ends. Repeated whole-map propagation was quadratic for long chains.
    // Marking before descent also terminates cycles, which retain an unknown
    // API. This iterative walk keeps hostile chains off the call stack.
    std::vector<ThunkInfo*> chain;
    for (auto& [address, root] : thunks) {
        if (stopped()) return {};
        (void)address;
        if (root.resolved) continue;
        chain.clear();
        ThunkInfo* current = &root;
        while (current && !current->resolved) {
            if ((chain.size() & 0xFFu) == 0 && stopped()) return {};
            current->resolved = true;
            chain.push_back(current);
            if (!current->api.empty()) break;
            const auto next = current->targetValid ? thunks.find(current->target) : thunks.end();
            current = next == thunks.end() ? nullptr : &next->second;
        }
        if (current && !current->api.empty()) {
            for (size_t i = 0; i < chain.size(); ++i) {
                if ((i & 0xFFu) == 0 && stopped()) return {};
                chain[i]->api = current->api;
            }
        }
    }

    // ---- Pass 2: full evidence + synthesis. ----
    // Keep synthesis separate from allocation so we know exactly which anonymous
    // originals will remain occupied before assigning any guessed names.
    std::vector<GuessedName> synthesized(funcs.size());

    for (size_t i = 0; i < funcs.size(); ++i) {
        if (stopped()) return {};
        const NamerInput& f = funcs[i];
        out[i].name = f.name;                 // default: keep existing name
        if (!isGuessable(f)) continue;

        FuncEvidence e;
        const bool isStart = startValid && f.address == startVA;
        e.isRawStart = isStart && rawAnalysisStart;
        e.isEntry    = isStart && !rawAnalysisStart;
        if (auto it = thunks.find(f.address); it != thunks.end()) {
            e.isThunk  = it->second.isThunk;
            e.thunkApi = it->second.api;
        }

        size_t win = 0;
        const uint8_t* p = bodyBytes(f, win);
        auto insns = p ? dis.disassemble(p, win, f.address, 512)
                       : std::vector<Instruction>{};
        if (stopped()) return {};
        // Keep decoder output within this function's bounded window. A size
        // estimate must never let the next declared function donate evidence.
        insns.erase(std::remove_if(insns.begin(), insns.end(), [&](const auto& in) {
            return !in.length || in.address < f.address || in.address - f.address >= win ||
                   in.length > win - (in.address - f.address);
        }), insns.end());
        e.bodySampled = insns.size() >= 512 || (f.size && win < f.size);

        // A bounded entry-reachability walk excludes post-RET data, skipped
        // blocks, and neighboring fallthroughs without another CFG/decode pass.
        // Delay slots execute before the transfer; include them but do not
        // invent their own fallthrough edge into the skipped block.
        std::unordered_map<uint64_t, size_t> instructionAt;
        for (size_t j = 0; j < insns.size(); ++j) instructionAt.emplace(insns[j].address, j);
        std::vector<bool> reachable(insns.size());
        std::vector<size_t> pending;
        std::unordered_set<uint64_t> leaders;
        const auto enqueue = [&](uint64_t address, bool branchTarget) {
            if (branchTarget) leaders.insert(address);
            const auto found = instructionAt.find(address);
            if (found == instructionAt.end()) { e.bodySampled = true; return; }
            if (!reachable[found->second]) {
                reachable[found->second] = true;
                pending.push_back(found->second);
            }
        };
        enqueue(f.address, false);
        for (size_t cursor = 0; cursor < pending.size(); ++cursor) {
            if ((cursor & 0x3Fu) == 0 && stopped()) return {};
            const size_t index = pending[cursor];
            const auto& in = insns[index];
            if (in.address > (std::numeric_limits<uint64_t>::max)() - in.length) {
                // A final-byte return needs no representable successor.
                if (!InstructionIsReturn(in) || in.flow.delaySlots) e.bodySampled = true;
                continue;
            }
            uint64_t next = in.address + in.length;
            for (size_t slot = 0; slot < in.flow.delaySlots; ++slot) {
                const auto found = instructionAt.find(next);
                if (found == instructionAt.end()) { e.bodySampled = true; break; }
                reachable[found->second] = true;
                if (next > (std::numeric_limits<uint64_t>::max)() - insns[found->second].length) {
                    e.bodySampled = true; break;
                }
                next += insns[found->second].length;
            }
            if (InstructionIsReturn(in) || InstructionIsSubroutineReturn(in)) continue;
            if (!InstructionIsCall(in) && InstructionEndsBlock(in)) {
                uint64_t target = 0;
                bool hasSuccessor = false;
                if (TryGetDirectTarget(in, target)) { enqueue(target, true); hasSuccessor = true; }
                if (in.switchInfo.defaultTargetValid) enqueue(in.switchInfo.defaultTarget, true);
                size_t edges = 0;
                for (const auto& item : in.switchInfo.cases) {
                    if (++edges > 512) { e.bodySampled = true; break; }
                    if (item.targetValid) { enqueue(item.target, true); hasSuccessor = true; }
                    else e.bodySampled = true;
                }
                for (const uint64_t extra : in.extraTargets) {
                    if (++edges > 512) { e.bodySampled = true; break; }
                    enqueue(extra, true); hasSuccessor = true;
                }
                if (!hasSuccessor && !in.switchInfo.defaultTargetValid) e.bodySampled = true;
                if (!isConditionalBranch(in) && !InstructionIsSubroutineCall(in)) continue;
            }
            enqueue(next, false);
        }
        size_t retained = 0;
        for (size_t j = 0; j < insns.size(); ++j)
            if (reachable[j]) {
                if (j != retained) insns[retained] = std::move(insns[j]);
                ++retained;
            }
        insns.resize(retained);
        int meaningful = 0;     // instrs that aren't padding/frame noise
        int retCount = 0;
        bool accKnownZero = false, allReturnsZero = true, hasControlBranch = false;
        bool trivialZeroBody = true;
        // Track the first local use of any imported API's accumulator result.
        // The old connectivity-only state could prove WifiCheck but could not
        // tell a checked memcmp from a checked CryptHashData status.
        std::string resultAccumulatorApi;
        std::string resultCompareApi;
        std::string resultX86CompareApi;
        std::string resultSetccAlApi;
        std::string resultNormalizedAccumulatorApi;
        auto clearResultFlow = [&] {
            resultAccumulatorApi.clear();
            resultCompareApi.clear();
            resultX86CompareApi.clear();
            resultSetccAlApi.clear();
            resultNormalizedAccumulatorApi.clear();
        };
        auto recordResultUse = [&](const std::string& api, bool checked,
                                   bool returned, bool normalizedReturned) {
            const std::string key = compactApiKey(api);
            if (key.empty()) return;
            auto it = std::find_if(e.apiResultUses.begin(), e.apiResultUses.end(),
                [&](const ApiResultUseEvidence& existing) {
                    return compactApiKey(existing.api) == key;
                });
            if (it == e.apiResultUses.end()) {
                if (e.apiResultUses.size() >= 32) return;
                e.apiResultUses.push_back({api, checked, returned, normalizedReturned});
            } else {
                it->checked = it->checked || checked;
                it->returned = it->returned || returned;
                it->normalizedReturned = it->normalizedReturned || normalizedReturned;
            }
            if (isConnectivityPredicateApi(api)) {
                e.connectivityResultChecked = e.connectivityResultChecked || checked;
                e.connectivityResultReturned = e.connectivityResultReturned || returned;
            }
        };
        std::unordered_set<std::string> apiSeen, strSeen;
        std::vector<std::pair<uint64_t, std::string>> actionStrings;
        uint64_t previousEnd = f.address;
        for (const auto& in : insns) {
            if ((e.instrCount & 0x3Fu) == 0 && stopped()) return {};
            ++e.instrCount;
            // Linear adjacency is insufficient at a merge: another predecessor
            // may have supplied a different accumulator or flags value.
            if (in.address != previousEnd || leaders.count(in.address)) {
                clearResultFlow();
                accKnownZero = false;
            }
            previousEnd = in.address <= (std::numeric_limits<uint64_t>::max)() - in.length
                ? in.address + in.length : in.address;
            bool noise = isFrameNoise(in, retCount != 0);
            if (!noise) ++meaningful;
            const bool instructionCall = InstructionIsCall(in);
            const bool instructionReturn = InstructionIsReturn(in);
            if (!instructionReturn && !noise && !zeroesAccumulator(in))
                trivialZeroBody = false;
            if (instructionReturn) {
                if (!resultNormalizedAccumulatorApi.empty())
                    recordResultUse(resultNormalizedAccumulatorApi, false, true, true);
                else if (!resultAccumulatorApi.empty())
                    recordResultUse(resultAccumulatorApi, false, true, false);
                clearResultFlow();
                ++retCount;
                allReturnsZero = allReturnsZero && accKnownZero;
                continue;
            }
            if ((in.isBranch && !instructionCall) ||
                (in.flow.kind != FlowKind::None && InstructionEndsBlock(in)))
                hasControlBranch = true;

            if (instructionCall) {
                ++e.callCount;
                accKnownZero = false;                                // x86 calls return through eax/rax
                clearResultFlow();
                std::string nm = resolveTargetApi(in);
                uint64_t target = 0;
                if (nm.empty() && TryGetDirectTarget(in, target)) {   // call to another local fn?
                    if (target == f.address) e.selfRecursive = true;
                    else if (auto it = thunks.find(target); it != thunks.end() && !it->second.api.empty())
                        nm = it->second.api;                          // call to a thunk -> its API
                }
                std::string bare = bareApi(nm);
                if (!bare.empty() && !isNoiseApi(bare)) {
                    resultAccumulatorApi = bare;
                    if (e.apiCallSequence.size() < 64) e.apiCallSequence.push_back(bare);
                    if (apiSeen.insert(norm(bare)).second) e.apis.push_back(bare);
                }
            } else {
                if (isConditionalBranch(in)) {
                    if (!resultCompareApi.empty() && isZeroEqualityBranch(in))
                        recordResultUse(resultCompareApi, true, false, false);
                    else if (!resultAccumulatorApi.empty() && branchTestsAccumulatorForZero(in))
                        recordResultUse(resultAccumulatorApi, true, false, false);
                    // A linear scan cannot safely follow the accumulator through
                    // both successors.  The decision evidence above is enough.
                    clearResultFlow();
                } else if (!resultAccumulatorApi.empty() &&
                           normalizesAccumulatorDirectly(in)) {
                    const std::string source = resultAccumulatorApi;
                    clearResultFlow();
                    resultAccumulatorApi = source;
                    resultNormalizedAccumulatorApi = source;
                } else if (!resultAccumulatorApi.empty() && testsAccumulatorForZero(in)) {
                    resultCompareApi = resultAccumulatorApi;
                    resultX86CompareApi = testsFullX86AccumulatorForZero(in)
                        ? resultAccumulatorApi : std::string();
                    resultSetccAlApi.clear();
                    resultNormalizedAccumulatorApi.clear();
                } else if (!resultCompareApi.empty() &&
                           setsZeroEqualityIntoAarch64Accumulator(in)) {
                    const std::string source = resultCompareApi;
                    clearResultFlow();
                    resultAccumulatorApi = source;
                    resultNormalizedAccumulatorApi = source;
                } else if (!resultX86CompareApi.empty() && setsZeroEqualityIntoAl(in)) {
                    // SETE/SETNE consumes the immediately preceding zero-test
                    // flags, but AL is only a partial architectural return. Wait
                    // for the canonical MOVZX before granting return evidence.
                    resultAccumulatorApi.clear();
                    resultCompareApi.clear();
                    resultSetccAlApi = resultX86CompareApi;
                    resultX86CompareApi.clear();
                    resultNormalizedAccumulatorApi.clear();
                } else if (!resultSetccAlApi.empty() && zeroExtendsAlIntoEax(in)) {
                    resultAccumulatorApi = resultSetccAlApi;
                    resultCompareApi.clear();
                    resultX86CompareApi.clear();
                    resultNormalizedAccumulatorApi = resultSetccAlApi;
                    resultSetccAlApi.clear();
                } else if (isReturnValueTransparentFrameOp(in)) {
                    // Preserve EAX across ABI teardown. Only true frame-noise
                    // instructions may also sit between TEST/CMP and its Jcc;
                    // ADD rsp/esp changes flags and therefore breaks that pair.
                    if (!noise) {
                        resultCompareApi.clear();
                        resultX86CompareApi.clear();
                        resultSetccAlApi.clear();
                    }
                } else {
                    clearResultFlow();
                }

                // String reference?
                uint64_t d = 0;
                bool hasDataRef = TryGetInstrDataRef(in, d);
                if (!hasDataRef) hasDataRef = TryGetInstrImmRef(in, d); // x86-32 offset string, VA 0 valid
                if (hasDataRef && stringRefFor) {
                    std::string s = stringRefFor(d);
                    if (!s.empty() && s.size() <= 2048 && actionStrings.size() < 64)
                        actionStrings.emplace_back(in.address, s);
                    if (!s.empty() && e.strings.size() < 32 && strSeen.insert(s).second)
                        e.strings.push_back(s);
                }
                if (zeroesAccumulator(in)) accKnownZero = true;
                else if (writesAccumulator(in)) accKnownZero = false;
            }
        }
        e.retOnly = (e.callCount == 0 && retCount == 1 && !hasControlBranch && meaningful <= 1);
        e.retZero = (e.callCount == 0 && retCount == 1 && !hasControlBranch &&
                     allReturnsZero && trivialZeroBody && meaningful <= 4);

        if (!e.bodySampled && e.callCount == 0 &&
            (bin.machine() == MachineArch::X86 || bin.machine() == MachineArch::X64 ||
             bin.machine() == MachineArch::Unknown))
            e.scalarFunction = scalarLeafEvidence(insns, bin.machine() == MachineArch::X64);

        if (!actionStrings.empty() && e.instrCount <= 192 && e.callCount <= 8 &&
            (bin.machine() == MachineArch::X86 || bin.machine() == MachineArch::X64 ||
             bin.machine() == MachineArch::Unknown)) {
            std::unordered_set<uint64_t> leaders;
            for (const auto& in : insns) {
                uint64_t target = 0;
                if (!InstructionIsCall(in) && TryGetDirectTarget(in, target)) leaders.insert(target);
            }
            // Split at transfers and incoming branch targets, preserving the
            // streaming pass's bounded body rather than constructing a new CFG.
            std::vector<Instruction> block;
            const auto collect = [&] {
                if (block.empty() || e.stringActions.size() >= 16) return;
                const auto mutations = FindStringActionMutations(block,
                    bin.machine() == MachineArch::X86 ? Arch::X86 : Arch::X64);
                for (const auto& mutation : mutations) {
                    if (mutation.kind == StringActionKind::Write) continue;
                    auto operation = std::find_if(block.begin(), block.end(), [&](const auto& in) {
                        return in.address == mutation.instructionVA;
                    });
                    for (const auto& reference : actionStrings) {
                        auto literal = std::find_if(block.begin(), block.end(), [&](const auto& in) {
                            return in.address == reference.first;
                        });
                        if (literal == block.end() || operation == block.end() ||
                            std::abs(std::distance(literal, operation)) > 48) continue;
                        if (e.stringActions.size() >= 16) return;
                        e.stringActions.push_back({reference.second, mutation.instructionVA,
                            reference.first, mutation.kind == StringActionKind::Add,
                            mutation.kind == StringActionKind::Subtract, true});
                    }
                }
            };
            for (const auto& in : insns) {
                if (stopped()) return {};
                if (!block.empty() && (leaders.count(in.address) ||
                    block.back().address > (std::numeric_limits<uint64_t>::max)() - block.back().length ||
                    block.back().address + block.back().length != in.address)) {
                    collect(); block.clear();
                }
                block.push_back(in);
                if (InstructionEndsBlock(in)) { collect(); block.clear(); }
            }
            collect();
        }

        GuessedName g = GuessFromEvidence(e);
        if (!g.guessed) continue;
        if (e.bodySampled && !(e.isThunk && !e.thunkApi.empty()) && !e.isEntry && !e.isRawStart)
            g.reason += "; bounded body sample; remaining instructions not inspected";
        synthesized[i] = std::move(g);
    }

    // Reserve every current name, including anonymous names that will remain
    // unguessed.  Release all originals known to be replaced, then allocate in
    // stable function order.  This avoids both duplicate unresolved sub_ names
    // and needless suffixes for placeholders that another guess will vacate.
    std::unordered_map<std::string, size_t> used;
    for (const auto& f : funcs) {
        if (stopped()) return {};
        if (!f.name.empty()) ++used[nameKey(f.name)];
    }
    for (size_t i = 0; i < funcs.size(); ++i) {
        if (stopped()) return {};
        if (!synthesized[i].guessed) continue;
        const std::string oldKey = nameKey(funcs[i].name);
        if (auto it = used.find(oldKey); it != used.end()) {
            if (it->second > 1) --it->second;
            else used.erase(it);
        }
    }

    // Assigned names only accumulate from here. A suffix already occupied for
    // one case-insensitive base can never become available later, so remember
    // where its search stopped instead of restarting at _1 for every function.
    std::unordered_map<std::string, size_t> nextSuffix;
    for (size_t i = 0; i < funcs.size(); ++i) {
        if (stopped()) return {};
        GuessedName& g = synthesized[i];
        if (!g.guessed) continue;
        std::string base = g.name, cand = base;
        const std::string baseKey = nameKey(base);
        if (used.count(baseKey)) {
            size_t& suffix = nextSuffix[baseKey];
            if (!suffix) suffix = 1;
            do {
                if ((suffix & 0xFFu) == 0 && stopped()) return {};
                cand = base + "_" + std::to_string(suffix++);
            } while (used.count(nameKey(cand)));
        }
        ++used[nameKey(cand)];
        if (cand != base)
            g.reason += "; name \"" + base + "\" already existed, shown as \"" + cand + "\"";
        out[i].name    = std::move(cand);
        out[i].reason  = std::move(g.reason);
        out[i].guessed = true;
        ++guessed_;
    }

    if (stopped()) return {};
    return out;
}

} // namespace ds
