#include "Cortex.h"

#include "AlgoScan.h"
#include "AnalysisJobs.h"   // FuncResult, StrResult
#include "BinaryFile.h"
#include "TechScan.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace ds {

namespace {

constexpr size_t kMaxAddrsPerBehavior = 32;
constexpr size_t kMaxHighlights       = 16;

std::string lower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

bool has(const std::string& hay, const char* sub) {
    return hay.find(sub) != std::string::npos;
}

// Does the lowercased haystack contain any of the given lowercase substrings?
bool hasAny(const std::string& lowHay, std::initializer_list<const char*> subs) {
    for (const char* s : subs) if (lowHay.find(s) != std::string::npos) return true;
    return false;
}

// Match a lower-case identifier as a token, so Win32 names such as SendMessage
// do not accidentally satisfy the socket API token "send".
bool hasToken(const std::string& lowHay, const char* token) {
    const size_t n = std::char_traits<char>::length(token);
    size_t at = 0;
    while ((at = lowHay.find(token, at)) != std::string::npos) {
        const bool left = at == 0 || !std::isalnum((unsigned char)lowHay[at - 1]);
        const size_t end = at + n;
        const bool right = end == lowHay.size() || !std::isalnum((unsigned char)lowHay[end]);
        if (left && right) return true;
        ++at;
    }
    return false;
}

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v);
    return b;
}

std::string titleCase(const std::string& s) {
    std::string t = s;
    if (!t.empty()) t[0] = (char)std::toupper((unsigned char)t[0]);
    return t;
}

float confidence01(float c) {
    if (!(c >= 0.0f)) return 0.0f; // also rejects NaN
    return c > 1.0f ? 1.0f : c;
}

const char* archName(MachineArch m) {
    switch (m) {
        case MachineArch::X86:     return "x86";
        case MachineArch::X64:     return "x64";
        case MachineArch::ARM:     return "ARM";
        case MachineArch::ARM64:   return "ARM64";
        case MachineArch::MIPS:    return "MIPS";
        case MachineArch::MIPS64:  return "MIPS64";
        case MachineArch::PPC:     return "PowerPC";
        case MachineArch::PPC64:   return "PPC64";
        case MachineArch::RISCV:   return "RISC-V";
        case MachineArch::RISCV64: return "RISC-V 64";
        case MachineArch::JVM:     return "JVM bytecode";
        default:                   return "unknown";
    }
}

// Canonical presentation for a behaviour category: a human title, a plain-English
// explanation, and a short verb phrase for the one-line headline. Categories not
// listed fall back to a title-cased bucket with no explanation.
struct CatInfo { const char* title; const char* explain; const char* verb; };

const CatInfo* catInfo(const std::string& cat) {
    static const std::map<std::string, CatInfo> kMap = {
        { "network",    { "Network communication", "Talks over the network (sockets or HTTP) — it can download, exfiltrate, or receive commands.", "communicates over the network" } },
        { "crypto",     { "Cryptography", "Contains cryptographic code used to encrypt or decrypt data (also common in ransomware and licensing).", "uses cryptography" } },
        { "hash",       { "Hashing / integrity", "Computes cryptographic hashes — for integrity checks, password handling, or fingerprinting.", "computes hashes" } },
        { "encoding",   { "Encoding (Base64/…)", "Encodes or decodes data (e.g. Base64) — often used to wrap payloads or obfuscate strings.", "encodes/decodes data" } },
        { "checksum",   { "Checksums (CRC/…)", "Computes checksums such as CRC32 for integrity or table-driven validation.", "computes checksums" } },
        { "anti-debug", { "Anti-debugging", "Checks whether it is being debugged and may change behaviour if so — a sign of protection or evasion.", "checks for a debugger" } },
        { "evasion",    { "Evasion (direct syscalls)", "Invokes the kernel directly through syscall stubs, bypassing user-mode API hooks — a defence-evasion technique.", "uses direct syscalls" } },
        { "injection",  { "Process injection / hooking", "Can write into and run code inside another process — used by injectors, hooks, and malware.", "injects code into other processes" } },
        { "dynamic",    { "Dynamic API resolution", "Resolves API addresses at runtime (LoadLibrary/GetProcAddress), hiding which APIs it really uses from the static import table.", "resolves APIs at runtime" } },
        { "spawn",      { "Process / command execution", "Launches other programs or shell commands.", "runs other programs" } },
        { "packer",     { "Packed / protected", "The image looks packed or protected, so the real code is hidden until it unpacks itself at runtime — static analysis will be incomplete.", "is packed/protected" } },
        { "java",       { "Java / JVM payload", "Bundles or launches a Java payload — the real logic lives in embedded class/JAR bytecode, not this native stub.", "launches a Java payload" } },
        { "filesystem", { "File access", "Reads or writes files on disk.", "reads and writes files" } },
        { "registry",   { "Registry access", "Reads or writes the Windows registry — often for configuration or persistence.", "touches the registry" } },
        { "gui",        { "Graphical interface", "Creates windows and message loops — it has a GUI.", "has a graphical interface" } },
        { "service",    { "Windows service", "Installs or controls a Windows service — a common persistence mechanism.", "installs/controls a service" } },
        { "clipboard",  { "Clipboard access", "Reads or writes the clipboard.", "accesses the clipboard" } },
        { "keylog",     { "Keyboard monitoring", "Polls keyboard state — possible keylogging.", "monitors the keyboard" } },
    };
    auto it = kMap.find(cat);
    return it == kMap.end() ? nullptr : &it->second;
}

std::string catTitle(const std::string& cat) {
    if (const CatInfo* ci = catInfo(cat)) return ci->title;
    return titleCase(cat);
}

const char* confWord(float c) {
    if (c >= 0.80f) return "very likely";
    if (c >= 0.60f) return "likely";
    if (c >= 0.40f) return "possibly";
    return "maybe";
}

// A canned brief for a recognised heuristic function name (FunctionNamer's
// semantic verbs). "" if the name isn't one we have phrasing for.
std::string briefForGuessName(const std::string& name) {
    static const std::map<std::string, std::string> kMap = {
        { "read_file",       "Reads data from a file." },
        { "write_file",      "Writes data to a file." },
        { "open_file",       "Opens a file." },
        { "net_send",        "Sends data over a network socket." },
        { "net_recv",        "Receives data from a network socket." },
        { "net_connect",     "Opens a network connection." },
        { "http_request",    "Makes an HTTP request." },
        { "inject_thread",   "Injects and runs a thread in another process." },
        { "alloc_remote",    "Allocates memory inside another process." },
        { "read_registry",   "Reads a value from the registry." },
        { "write_registry",  "Writes a value to the registry." },
        { "encrypt_data",    "Encrypts or decrypts a buffer." },
        { "hash_data",       "Hashes a buffer." },
        { "spawn_process",   "Launches another process." },
        { "load_library",    "Loads a DLL at runtime." },
        { "resolve_api",     "Resolves an API address at runtime." },
        { "start",           "Program entry point / startup." },
        { "nullsub",         "Stub — does nothing." },
        { "ret_zero",        "Stub — returns zero." },
    };
    auto it = kMap.find(name);
    return it == kMap.end() ? std::string() : it->second;
}

// Append `s` to `dst` as a comma-joined clause, de-duplicating.
void addSpecific(std::vector<std::string>& v, const std::string& s) {
    if (s.empty()) return;
    if (std::find(v.begin(), v.end(), s) == v.end()) v.push_back(s);
}

std::string joinList(const std::vector<std::string>& v, size_t cap = 6) {
    std::string out;
    for (size_t i = 0; i < v.size() && i < cap; ++i) { if (i) out += ", "; out += v[i]; }
    if (v.size() > cap) out += ", …";
    return out;
}

// Supplemental import grouping for everyday behaviours TechScan deliberately omits
// (too common to flag as a "capability", but useful for description). Lowercase
// substrings matched against import names.
struct ImpRule { const char* cat; std::vector<const char*> keys; float base; };
const ImpRule kImpRules[] = {
    { "filesystem", { "createfile", "readfile", "writefile", "deletefile", "findfirstfile",
                      "movefile", "copyfile", "ntcreatefile", "ntreadfile", "ntwritefile",
                      "setfilepointer", "getfilesize" }, 0.55f },
    { "registry",   { "regopenkey", "regsetvalue", "regqueryvalue", "regcreatekey",
                      "regdeletekey", "regenumkey", "ntopenkey", "ntsetvaluekey" }, 0.6f },
    { "gui",        { "createwindow", "registerclass", "messagebox", "dialogbox",
                      "showwindow", "getmessage", "defwindowproc", "beginpaint" }, 0.5f },
    { "service",    { "openscmanager", "createservice", "startservice", "controlservice",
                      "registerservicectrl", "setservicestatus" }, 0.65f },
    { "clipboard",  { "getclipboarddata", "setclipboarddata", "openclipboard" }, 0.6f },
    { "keylog",     { "getasynckeystate", "getkeyboardstate", "getkeystate" }, 0.55f },
};

} // namespace

CortexReport BuildCortexReport(const CortexInput& in) {
    CortexReport rep;
    const BinaryFile* bin = in.bin;

    // ---- Behaviour merge: fold every piece of evidence into per-category buckets ----
    std::map<std::string, CortexBehavior> byCat;
    auto bucket = [&](const std::string& cat) -> CortexBehavior& {
        CortexBehavior& b = byCat[cat];
        if (b.category.empty()) {
            b.category = cat;
            b.title    = catTitle(cat);
            if (const CatInfo* ci = catInfo(cat)) b.explanation = ci->explain;
        }
        return b;
    };
    auto pushAddr = [](CortexBehavior& b, uint64_t va) {
        if (!va || b.addresses.size() >= kMaxAddrsPerBehavior) return;
        if (std::find(b.addresses.begin(), b.addresses.end(), va) == b.addresses.end())
            b.addresses.push_back(va);
    };
    auto addEvidence = [](CortexBehavior& b, const std::string& e) {
        if (e.empty()) return;
        if (!b.evidence.empty()) b.evidence += "; ";
        b.evidence += e;
    };

    // 1) TechScan capabilities.
    if (in.capabilities) {
        for (const Capability& c : *in.capabilities) {
            CortexBehavior& b = bucket(c.category);
            b.confidence = std::max(b.confidence, confidence01(c.confidence));
            addEvidence(b, c.detail);
            // Packer/java capability names carry the specific tool ("UPX packer").
            if (c.category == "packer" || c.category == "java") addSpecific(b.specifics, c.name);
            pushAddr(b, c.address);
            for (uint64_t va : c.addresses) pushAddr(b, va);
        }
    }

    // 2) AlgoScan matches (crypto/hash/encoding/checksum) — fold the algorithm name
    //    in as a specific, and pull in the functions that reference the constants.
    if (in.algorithms) {
        for (const AlgoMatch& a : *in.algorithms) {
            CortexBehavior& b = bucket(a.category);
            b.confidence = std::max(b.confidence, confidence01(a.confidence));
            addSpecific(b.specifics, a.name);
            addEvidence(b, a.detail);
            pushAddr(b, a.address);
            for (const AlgoXref& x : a.referencedBy) pushAddr(b, x.refInsn ? x.refInsn : x.funcAddress);
        }
    }

    // 3) Supplemental import grouping (Cortex's own everyday-behaviour buckets).
    if (bin && bin->loaded()) {
        std::vector<std::string> loweredImports;
        loweredImports.reserve(bin->imports().size());
        for (const auto& im : bin->imports()) loweredImports.push_back(lower(im.name));
        for (const ImpRule& r : kImpRules) {
            std::vector<std::string> hits;
            uint64_t addr = 0;
            for (size_t ii = 0; ii < bin->imports().size(); ++ii) {
                const auto& im = bin->imports()[ii];
                const std::string& ln = loweredImports[ii];
                for (const char* k : r.keys)
                    if (ln.find(k) != std::string::npos) {
                        if (std::find(hits.begin(), hits.end(), im.name) == hits.end()) hits.push_back(im.name);
                        if (!addr) addr = im.iatVA;
                        break;
                    }
            }
            if (hits.empty()) continue;
            CortexBehavior& b = bucket(r.cat);
            b.confidence = std::max(b.confidence, std::min(0.9f, r.base + 0.05f * (float)(hits.size() - 1)));
            addEvidence(b, "Imports: " + joinList(hits, 10));
            pushAddr(b, addr);
        }
    }

    // NOTE: rep.behaviors is populated at the very END — the headline/verdict/facts
    // below still read `byCat`, so it must stay intact until then.

    // ---- Per-function briefs ----
    // Map function-start VA -> algorithm names/categories it references. One function
    // may contain more than one class (for example CRC + AES), so do not overwrite
    // the category with the last match or default non-crypto matches to crypto.
    std::unordered_map<uint64_t, std::vector<std::string>> algoByFunc;
    std::unordered_map<uint64_t, std::vector<std::string>> algoCatsByFunc;
    if (in.algorithms)
        for (const AlgoMatch& a : *in.algorithms)
            for (const AlgoXref& x : a.referencedBy)
                if (x.funcAddress) {
                    addSpecific(algoByFunc[x.funcAddress], a.name);
                    addSpecific(algoCatsByFunc[x.funcAddress], a.category);
                }

    uint64_t entryAbs = (bin && bin->loaded() && bin->entryPoint())
                      ? bin->imageBase() + bin->entryPoint() : 0;

    // Per-function annotation facts (from FuncAnnotate, supplied by the caller).
    std::unordered_map<uint64_t, const CortexFuncInfo*> infoByFunc;
    if (in.funcInfo)
        for (const CortexFuncInfo& fi : *in.funcInfo) infoByFunc[fi.address] = &fi;

    auto addTag = [](std::vector<std::string>& tags, const char* t) {
        if (std::find(tags.begin(), tags.end(), t) == tags.end()) tags.push_back(t);
    };

    int guessedFuncs = 0;
    if (in.functions) {
        for (const FuncResult& f : *in.functions) {
            CortexFuncBrief fb;
            fb.address = f.address;
            fb.name    = f.name;
            fb.guessed = f.guessed;
            fb.basis   = f.reason;
            if (f.guessed) ++guessedFuncs;

            const CortexFuncInfo* info = nullptr;
            { auto it = infoByFunc.find(f.address); if (it != infoByFunc.end()) info = it->second; }
            if (info) fb.convention = info->convention;

            std::string ln = lower(f.name);
            std::string lr = lower(f.reason);
            bool isEntry = (entryAbs && f.address == entryAbs) || f.name == "start";

            // Tags — from the name/reason, the crypto-constant xref, and annotation patterns.
            if (isEntry) addTag(fb.tags, "entry");
            auto ai = algoByFunc.find(f.address);
            if (ai != algoByFunc.end()) {
                auto ci = algoCatsByFunc.find(f.address);
                if (ci != algoCatsByFunc.end())
                    for (const std::string& cat : ci->second) addTag(fb.tags, cat.c_str());
            }
            if (hasAny(lr, { "socket", "wsasend", "wsarecv", "sendto", "recvfrom", "winhttp",
                             "wininet", "internetopen", "internetconnect", "http", "curl" }) ||
                hasToken(lr, "send") || hasToken(lr, "recv") || hasToken(lr, "connect") ||
                hasAny(ln, { "net_", "http_", "socket", "net_send", "net_recv", "net_connect" }))
                addTag(fb.tags, "network");
            if (hasAny(lr, { "createfile", "readfile", "writefile", "deletefile", "copyfile", "movefile" }) ||
                hasAny(ln, { "read_file", "write_file", "open_file", "_file" })) addTag(fb.tags, "file");
            if (hasAny(lr, { "regopenkey", "regcreatekey", "regqueryvalue", "regsetvalue",
                             "regdeletekey", "registry" }) ||
                hasAny(ln, { "read_registry", "write_registry", "registry", "regkey" }))
                addTag(fb.tags, "registry");
            if (hasAny(lr, { "virtualalloc", "writeprocessmemory", "createremotethread", "inject" }) ||
                hasAny(ln, { "inject" })) addTag(fb.tags, "inject");
            if (info) {
                for (const std::string& p : info->patterns) {
                    std::string lp = lower(p);
                    if (hasAny(lp, { "network", "socket", "http" }))                 addTag(fb.tags, "network");
                    if (hasAny(lp, { "file", "config" }))                            addTag(fb.tags, "file");
                    if (hasAny(lp, { "registr" }))                                   addTag(fb.tags, "registry");
                    if (hasAny(lp, { "inject", "remote thread" }))                   addTag(fb.tags, "inject");
                    if (hasAny(lp, { "encrypt", "decrypt", "cipher", "cryptograph", "aes", "chacha", "xtea", "rc4" }))
                        addTag(fb.tags, "crypto");
                    if (hasAny(lp, { "checksum", "crc" }))                       addTag(fb.tags, "checksum");
                    if (hasAny(lp, { "hash", "digest", "sha-", "md5" }))       addTag(fb.tags, "hash");
                    if (hasAny(lp, { "decode", "encode", "base64", "xor" }))   addTag(fb.tags, "encoding");
                    if (hasAny(lp, { "input", "reads user" }))                       addTag(fb.tags, "input");
                    if (hasAny(lp, { "loop", "message", "update", "timer" }))        addTag(fb.tags, "loop");
                }
            }

            // Brief text (priority: structural signals first, then the richest description).
            std::string canned     = briefForGuessName(f.name);
            std::string annoSummary = info ? info->summary : std::string();
            std::string sentenced;   // annotation summary, sentence-cased (set if used)
            if (isEntry) {
                fb.brief = "Program entry point — startup/CRT init, then reaches main.";
                fb.interest += 5.0f;
            } else if (ln.rfind("j_", 0) == 0 || has(lr, "thunk")) {
                fb.brief = "Import thunk — forwards straight to " +
                           (f.name.rfind("j_", 0) == 0 ? f.name.substr(2) : std::string("an API")) + ".";
                fb.interest += 0.5f;
            } else if (ai != algoByFunc.end()) {
                auto ci = algoCatsByFunc.find(f.address);
                std::string cats = ci != algoCatsByFunc.end() ? joinList(ci->second, 3) : std::string("algorithm");
                fb.brief = "References " + joinList(ai->second, 3) + " constants — part of a " + cats + " routine.";
                fb.interest += 4.0f;
            } else if (!canned.empty()) {
                fb.brief = canned;
                fb.interest += 3.0f;
            } else if (!annoSummary.empty()) {
                sentenced = annoSummary;
                if (!sentenced.empty()) sentenced[0] = (char)std::toupper((unsigned char)sentenced[0]);
                if (!sentenced.empty() && sentenced.back() != '.') sentenced += '.';
                fb.brief = sentenced;
                fb.interest += 3.0f;
            } else if (info && !info->patterns.empty()) {
                fb.brief = "Appears to " + joinList(info->patterns, 3) + ".";
                fb.interest += 2.5f;
            } else if (f.guessed && !f.reason.empty()) {
                fb.brief = "Heuristically named — " + f.reason + ".";
                fb.interest += 2.5f;
            } else {
                char sz[48]; std::snprintf(sz, sizeof(sz), "Function (~%u bytes).", f.size);
                fb.brief = sz;
            }

            // Keep the annotation summary in `basis` (tooltip) when it wasn't the brief.
            if (!annoSummary.empty() && fb.brief != sentenced) {
                if (!fb.basis.empty()) fb.basis += " · ";
                fb.basis += annoSummary;
            }

            // Interest bonuses.
            if (!fb.tags.empty()) fb.interest += 0.8f * (float)fb.tags.size();
            if (info && (!annoSummary.empty() || !info->patterns.empty())) fb.interest += 1.5f;
            fb.interest += std::min(3.0f, (float)f.size / 512.0f);

            rep.functions.push_back(std::move(fb));
        }
    }

    // Highlights: the most interesting functions, ranked.
    rep.highlights = rep.functions;
    std::sort(rep.highlights.begin(), rep.highlights.end(),
              [](const CortexFuncBrief& a, const CortexFuncBrief& b) { return a.interest > b.interest; });
    rep.highlights.erase(std::remove_if(rep.highlights.begin(), rep.highlights.end(),
                         [](const CortexFuncBrief& f) { return f.interest < 1.5f; }), rep.highlights.end());
    if (rep.highlights.size() > kMaxHighlights) rep.highlights.resize(kMaxHighlights);

    // ---- Headline + verdict ----
    std::string kindNoun = "program";
    bool packed = byCat.count("packer") > 0;
    bool isJava = byCat.count("java") > 0 || (bin && bin->format() == BinFormat::JavaClass);
    bool managed = bin && bin->clrDirRVA() != 0;
    if (bin && bin->loaded()) {
        switch (bin->format()) {
            case BinFormat::JavaClass: kindNoun = "Java class file"; break;
            case BinFormat::Raw:       kindNoun = "raw code blob"; break;
            default:                   kindNoun = "executable"; break;
        }
    }

    std::string archPart;
    if (!in.effectiveArchitecture.empty()) {
        archPart = in.effectiveArchitecture + " ";
        if (managed) archPart = ".NET " + archPart;
    } else if (bin && bin->loaded() && bin->machine() != MachineArch::Unknown) {
        archPart = std::string(archName(bin->machine())) + " ";
        if (managed) archPart = ".NET " + archPart;
    }

    // Collect verb phrases from the highest-confidence behaviours, in a priority order.
    static const char* kOrder[] = { "injection", "network", "spawn", "crypto", "hash",
                                    "checksum", "encoding", "anti-debug", "evasion", "registry",
                                    "filesystem", "service", "keylog", "clipboard", "gui",
                                    "dynamic", "packer" };
    std::vector<std::string> verbs;
    std::set<std::string> used;
    for (const char* c : kOrder) {
        auto it = byCat.find(c);
        if (it == byCat.end() || it->second.confidence < 0.4f) continue;
        const CatInfo* ci = catInfo(c);
        if (!ci) continue;
        std::string v = ci->verb;
        // Enrich crypto/hash/packer verbs with the specific name(s).
        if (!it->second.specifics.empty() && (std::string(c) == "crypto" || std::string(c) == "hash" ||
                                              std::string(c) == "checksum" || std::string(c) == "packer" ||
                                              std::string(c) == "encoding"))
            v += " (" + joinList(it->second.specifics, 3) + ")";
        verbs.push_back(v);
        used.insert(c);
        if (verbs.size() >= 4) break;
    }

    if (verbs.empty()) {
        rep.headline = "This looks like a " + archPart + kindNoun +
                       " with no notable networking, crypto, or evasion signatures.";
    } else {
        std::string vs;
        for (size_t i = 0; i < verbs.size(); ++i) {
            if (i && i + 1 == verbs.size()) vs += (verbs.size() > 2 ? ", and " : " and ");
            else if (i) vs += ", ";
            vs += verbs[i];
        }
        rep.headline = "This appears to be a " + archPart + kindNoun + " that " + vs + ".";
    }

    // Verdict paragraph.
    std::string v = rep.headline;
    if (packed) {
        auto& b = byCat["packer"];
        v += " It " + std::string(confWord(b.confidence)) + " " +
             (b.specifics.empty() ? "is packed" : ("is packed with " + joinList(b.specifics, 2))) +
             ", so what you see statically is only the unpacker — run it under the debugger to reach the real code.";
    }
    if (byCat.count("anti-debug")) {
        v += " It contains anti-debugging checks, so it may behave differently while a debugger is attached.";
    }
    if (isJava) {
        v += " A Java payload is present — the real logic is in the embedded bytecode; open the JAR/class to analyse it.";
    }
    // String-derived hints (URLs, paths, registry keys).
    if (in.strings) {
        std::string url, regkey;
        for (const StrResult& s : *in.strings) {
            std::string ls = lower(s.text);
            if (url.empty() && (has(ls, "http://") || has(ls, "https://"))) url = s.text;
            if (regkey.empty() && has(ls, "hkey_")) regkey = s.text;
            if (!url.empty() && !regkey.empty()) break;
        }
        if (!url.empty()) v += " A URL is embedded in its strings (" + url.substr(0, 80) + ").";
        if (!regkey.empty()) v += " It references a registry key (" + regkey.substr(0, 80) + ").";
    }
    if (in.functions && !in.functions->empty()) {
        char c[128];
        std::snprintf(c, sizeof(c), " %zu functions were discovered (%d heuristically named).",
                      in.functions->size(), guessedFuncs);
        v += c;
    }
    rep.verdict = v;

    // ---- Quick facts ----
    if (bin && bin->loaded()) {
        std::string format = std::string("Format: ") + bin->formatName();
        if (bin->format() == BinFormat::ELF || bin->format() == BinFormat::MachO)
            format += bin->is64Bit() ? " (64-bit)" : " (32-bit)";
        rep.facts.push_back(std::move(format));
        if (!in.effectiveArchitecture.empty())
            rep.facts.push_back("Analysis architecture: " + in.effectiveArchitecture);
        else if (bin->machine() != MachineArch::Unknown)
            rep.facts.push_back(std::string("Architecture: ") + archName(bin->machine()));
        if (bin->entryPoint()) rep.facts.push_back("Entry point: " + hex(entryAbs));
        rep.facts.push_back("Imports: " + std::to_string(bin->imports().size()));
        if (managed) rep.facts.push_back(".NET managed assembly");
    }
    if (in.functions) {
        char c[96];
        std::snprintf(c, sizeof(c), "Functions: %zu (%d guessed)", in.functions->size(), guessedFuncs);
        rep.facts.push_back(c);
    }
    if (in.strings) rep.facts.push_back("Strings: " + std::to_string(in.strings->size()));
    if (packed) rep.facts.push_back("Packed: yes" + (byCat["packer"].specifics.empty() ? std::string() :
                                     " (" + joinList(byCat["packer"].specifics, 2) + ")"));

    // ---- Publish behaviours (byCat is no longer read after this) ----
    for (auto& kv : byCat) rep.behaviors.push_back(std::move(kv.second));
    std::sort(rep.behaviors.begin(), rep.behaviors.end(),
              [](const CortexBehavior& a, const CortexBehavior& b) { return a.confidence > b.confidence; });

    return rep;
}

// ------------------------------------------------------------------ AskCortex ----

namespace {

// Answer for one behaviour category, grounded in the report.
std::string answerCategory(const CortexReport& rep, const std::string& cat,
                           const char* yesLead, const char* noLine) {
    for (const CortexBehavior& b : rep.behaviors) {
        if (b.category != cat) continue;
        std::string a = std::string(yesLead) + " (" + confWord(b.confidence) + "). ";
        if (const CatInfo* ci = catInfo(cat)) a += std::string(ci->explain) + " ";
        if (!b.specifics.empty()) a += "Specifically: " + joinList(b.specifics, 6) + ". ";
        if (!b.evidence.empty()) a += "Evidence: " + b.evidence + ".";
        return a;
    }
    return noLine;
}

// Find a function the question names — either an explicit "0x...." address or a
// function name mentioned by name (longest match wins so a full name beats a short
// accidental hit). Returns nullptr when the question isn't about a specific function.
const CortexFuncBrief* findFunctionInQuestion(const CortexReport& rep, const std::string& qLower) {
    size_t hp = qLower.find("0x");
    if (hp != std::string::npos) {
        char* end = nullptr;
        const char* first = qLower.c_str() + hp;
        uint64_t va = std::strtoull(first, &end, 16);
        if (end && end > first + 2)
            for (const CortexFuncBrief& f : rep.functions) if (f.address == va) return &f;
    }
    const CortexFuncBrief* best = nullptr; size_t bestLen = 0;
    for (const CortexFuncBrief& f : rep.functions) {
        if (f.name.size() < 4) continue;
        std::string ln = lower(f.name);
        if (qLower.find(ln) != std::string::npos && ln.size() > bestLen) { best = &f; bestLen = ln.size(); }
    }
    return best;
}

// List functions carrying a given tag.
std::string functionsWithTag(const CortexReport& rep, const char* tag) {
    std::vector<std::string> names;
    for (const CortexFuncBrief& f : rep.functions)
        if (std::find(f.tags.begin(), f.tags.end(), tag) != f.tags.end())
            names.push_back(f.name + " @ " + hex(f.address));
    if (names.empty()) return {};
    return joinList(names, 12);
}

} // namespace

std::string AskCortex(const CortexReport& rep, const CortexInput& in, const std::string& question) {
    std::string q = lower(question);

    // Resolve a named/addressed function before broad intent phrases such as
    // "explain this"; otherwise that question returns the whole-binary verdict.
    if (const CortexFuncBrief* f = findFunctionInQuestion(rep, q)) {
        std::string a = f->name + " @ " + hex(f->address) + " — " + f->brief;
        if (!f->convention.empty()) a += " Calling convention: " + f->convention + ".";
        if (!f->tags.empty()) {
            a += " Tags: ";
            for (size_t i = 0; i < f->tags.size(); ++i) { if (i) a += ", "; a += f->tags[i]; }
            a += ".";
        }
        if (!f->basis.empty()) a += "  (" + f->basis + ")";
        return a;
    }

    // Overview / purpose.
    if (hasAny(q, { "what does it do", "what is this", "overview", "summary", "purpose",
                    "explain the", "explain this", "tell me about" }))
        return rep.verdict;

    // Crypto.
    if (hasAny(q, { "crypto", "encrypt", "decrypt", "cipher", "aes", "rc4", "rsa", "chacha", "xtea", "tea" })) {
        std::string a = answerCategory(rep, "crypto", "Yes — it contains cryptographic code",
                                       "No cryptographic API calls or known crypto constants were detected.");
        std::string fns = functionsWithTag(rep, "crypto");
        if (!fns.empty()) a += " Crypto-related functions: " + fns + ".";
        return a;
    }
    // Hashing.
    if (hasAny(q, { "hash", "sha", "md5", "digest", "checksum", "crc" }))
        return answerCategory(rep, (has(q, "crc") || has(q, "checksum")) ? "checksum" : "hash",
                              "Yes — it computes hashes/checksums",
                              "No hashing or checksum constants were detected.");
    // Encoding.
    if (hasAny(q, { "base64", "encode", "encoding" }))
        return answerCategory(rep, "encoding", "Yes — it encodes/decodes data",
                              "No Base64/encoding alphabets were detected.");
    // Network.
    if (hasAny(q, { "network", "socket", "http", "internet", "connect", "url", "download",
                    "exfil", "c2", "command and control", "server" })) {
        std::string a = answerCategory(rep, "network", "Yes — it communicates over the network",
                                       "No networking APIs were detected in the import table.");
        std::string fns = functionsWithTag(rep, "network");
        if (!fns.empty()) a += " Networking functions: " + fns + ".";
        return a;
    }
    // Files.
    if (hasAny(q, { "file", "disk", "read from", "write to", "filesystem" }))
        return answerCategory(rep, "filesystem", "Yes — it accesses files",
                              "No obvious file-I/O APIs were detected.");
    // Registry.
    if (has(q, "registry") || has(q, "regkey"))
        return answerCategory(rep, "registry", "Yes — it touches the registry",
                              "No registry APIs were detected.");
    // Packing.
    if (hasAny(q, { "pack", "unpack", "obfuscat", "protect", "upx", "vmprotect", "themida" }))
        return answerCategory(rep, "packer", "Yes — the image looks packed/protected",
                              "No packer section names were detected — the code is probably not packed (but a custom packer can still hide).");
    // Injection.
    if (hasAny(q, { "inject", "hook", "remote thread", "hollow" })) {
        std::string a = answerCategory(rep, "injection", "Yes — it has process-injection/hooking capability",
                                       "No process-injection APIs were detected.");
        std::string fns = functionsWithTag(rep, "inject");
        if (!fns.empty()) a += " Related functions: " + fns + ".";
        return a;
    }
    // Anti-debug / evasion.
    if (hasAny(q, { "debug", "anti", "vm", "sandbox", "evasion", "evade", "detect" })) {
        std::string ad = answerCategory(rep, "anti-debug", "Yes — it checks for a debugger", "");
        std::string ev = answerCategory(rep, "evasion", "It also uses direct syscalls to evade user-mode hooks", "");
        std::string a = ad.empty() ? std::string() : ad;
        if (!ev.empty()) a += (a.empty() ? "" : " ") + ev;
        return a.empty() ? "No anti-debugging or evasion signatures were detected." : a;
    }
    // Entry point.
    if (hasAny(q, { "entry", "entrypoint", "start", "main", "begin" })) {
        for (const CortexFuncBrief& f : rep.functions)
            if (std::find(f.tags.begin(), f.tags.end(), "entry") != f.tags.end())
                return "Entry point is " + f.name + " @ " + hex(f.address) + ". " + f.brief;
        if (in.bin && in.bin->loaded())
            return "Entry point is at " + hex(in.bin->imageBase() + in.bin->entryPoint()) +
                   " (no discovered function is anchored there).";
        return "No entry point is available (no binary loaded, or a raw blob).";
    }
    // Strings.
    if (has(q, "string")) {
        if (!in.strings || in.strings->empty()) return "No strings were extracted.";
        std::vector<std::string> notable;
        for (const StrResult& s : *in.strings) {
            std::string ls = lower(s.text);
            if (hasAny(ls, { "http://", "https://", "hkey_", ".dll", ".exe", "\\", "/", "key", "password", "token" }))
                notable.push_back(s.text.substr(0, 60));
            if (notable.size() >= 12) break;
        }
        if (notable.empty()) return std::to_string(in.strings->size()) + " strings were extracted; none look especially notable.";
        return "Notable strings: " + joinList(notable, 12) + ".";
    }
    // Imports.
    if (hasAny(q, { "import", "api", "which dll", "libraries" })) {
        if (!in.bin || !in.bin->loaded() || in.bin->imports().empty())
            return "No imports are available (statically linked, packed, or not a PE).";
        std::map<std::string, int> byDll;
        for (const auto& im : in.bin->imports()) byDll[im.dll]++;
        std::string a = std::to_string(in.bin->imports().size()) + " imports across " +
                        std::to_string(byDll.size()) + " modules: ";
        std::vector<std::string> parts;
        for (auto& kv : byDll) parts.push_back(kv.first + " (" + std::to_string(kv.second) + ")");
        return a + joinList(parts, 10) + ".";
    }
    // Function count / highlights.
    if (hasAny(q, { "how many function", "function count", "number of function", "notable function",
                    "interesting function", "important function", "which function" })) {
        std::string a = std::to_string(rep.functions.size()) + " functions. ";
        if (!rep.highlights.empty()) {
            a += "Most notable: ";
            std::vector<std::string> hs;
            for (const CortexFuncBrief& f : rep.highlights) hs.push_back(f.name + " (" + f.brief + ")");
            a += joinList(hs, 8);
        }
        return a;
    }

    // Fallback: the verdict plus a hint about what can be asked.
    return rep.verdict +
           "\n\n(Ask about: crypto, hashing, network, files, registry, packing, injection, "
           "anti-debugging, strings, imports, the entry point, a specific function, or notable functions.)";
}

// ------------------------------------------------------------ Markdown render ----

std::string RenderCortexMarkdown(const CortexReport& rep) {
    std::string m = "# Cortex analysis\n\n";
    m += "> " + rep.headline + "\n\n";
    if (!rep.verdict.empty()) m += rep.verdict + "\n\n";

    if (!rep.facts.empty()) {
        m += "## Facts\n\n";
        for (const std::string& f : rep.facts) m += "- " + f + "\n";
        m += "\n";
    }

    if (!rep.behaviors.empty()) {
        m += "## Behaviours\n\n";
        for (const CortexBehavior& b : rep.behaviors) {
            char pct[16]; std::snprintf(pct, sizeof(pct), "%d%%", (int)(b.confidence * 100.0f + 0.5f));
            m += "### " + b.title + "  _(" + pct + ")_\n\n";
            if (!b.explanation.empty()) m += b.explanation + "\n\n";
            if (!b.specifics.empty())   m += "- Specifics: " + joinList(b.specifics, 12) + "\n";
            if (!b.evidence.empty())    m += "- Evidence: " + b.evidence + "\n";
            m += "\n";
        }
    }

    if (!rep.highlights.empty()) {
        m += "## Notable functions\n\n";
        for (const CortexFuncBrief& f : rep.highlights) {
            m += "- **" + f.name + "** @ " + hex(f.address) + " — " + f.brief;
            if (!f.basis.empty()) m += "  _(" + f.basis + ")_";
            m += "\n";
        }
        m += "\n";
    }
    return m;
}

std::string RenderCortexHtml(const CortexReport& rep) {
    auto esc = [](const std::string& s) {
        std::string o; o.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&': o += "&amp;";  break;
                case '<': o += "&lt;";   break;
                case '>': o += "&gt;";   break;
                case '"': o += "&quot;"; break;
                case '\'': o += "&#39;";  break;
                default: o += c; break;
            }
        }
        return o;
    };

    std::string h =
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Cortex analysis</title><style>"
        "body{font-family:Segoe UI,Arial,sans-serif;background:#1e1f22;color:#dfe2e8;margin:24px;}"
        "h1,h2,h3{color:#8ab4f8}.headline{font-size:1.15em}.muted{color:#aeb4c0}"
        "table{border-collapse:collapse;width:100%;margin:8px 0 20px}"
        "td,th{border:1px solid #3a3d44;padding:6px 10px;text-align:left;vertical-align:top}"
        "th{background:#2a2d33}.addr{font-family:Consolas,monospace;color:#d2b36c}"
        "</style></head><body><h1>Cortex analysis</h1>";
    if (!rep.headline.empty()) h += "<p class=\"headline\">" + esc(rep.headline) + "</p>";
    if (!rep.verdict.empty()) h += "<p>" + esc(rep.verdict) + "</p>";

    if (!rep.facts.empty()) {
        h += "<h2>Facts</h2><ul>";
        for (const std::string& fact : rep.facts) h += "<li>" + esc(fact) + "</li>";
        h += "</ul>";
    }
    if (!rep.behaviors.empty()) {
        h += "<h2>Behaviours</h2><table><tr><th>Behaviour</th><th>Confidence</th><th>Evidence</th></tr>";
        for (const CortexBehavior& b : rep.behaviors) {
            char pct[16]; std::snprintf(pct, sizeof(pct), "%d%%", (int)(confidence01(b.confidence) * 100.0f + 0.5f));
            std::string detail = b.explanation;
            if (!b.specifics.empty()) {
                if (!detail.empty()) detail += " ";
                detail += "Specifics: " + joinList(b.specifics, 12) + ".";
            }
            if (!b.evidence.empty()) {
                if (!detail.empty()) detail += " ";
                detail += "Evidence: " + b.evidence;
            }
            h += "<tr><td>" + esc(b.title) + "</td><td>" + pct + "</td><td>" + esc(detail) + "</td></tr>";
        }
        h += "</table>";
    }
    if (!rep.highlights.empty()) {
        h += "<h2>Notable functions</h2><table><tr><th>Address</th><th>Function</th><th>Assessment</th></tr>";
        for (const CortexFuncBrief& f : rep.highlights) {
            std::string assessment = f.brief;
            if (!f.basis.empty()) assessment += " (" + f.basis + ")";
            h += "<tr><td class=\"addr\">" + hex(f.address) + "</td><td>" + esc(f.name) +
                 "</td><td>" + esc(assessment) + "</td></tr>";
        }
        h += "</table>";
    }
    h += "</body></html>";
    return h;
}

} // namespace ds
