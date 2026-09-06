#include "TechScan.h"
#include "AddressSpan.h"
#include "BinaryFile.h"
#include "JavaScan.h"
#include "NetworkApiCatalog.h"
#include "RuntimeScan.h"
#include "SigMatch.h"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace ds {

namespace {

// Cap the number of pattern hits we collect per capability so a giant data table
// (e.g. an S-box repeated many times) can't blow up memory; the true count is
// still surfaced separately so evidence isn't undercounted, only bounded.
constexpr size_t kMaxPatternHits = 64;

std::string lower(std::string s) { for (char& c : s) c = (char)std::tolower((unsigned char)c); return s; }

// Find ALL offsets of `pat` (with a wildcard mask) in `data`, bounded by
// kMaxPatternHits, via the shared masked Boyer-Moore-Horspool matcher. Returns
// the (bounded) hit offsets in ascending order. `totalOut` receives the true
// number of matches (which may exceed the returned vector when the cap is hit;
// when the cap is reached it reports at least the cap — exact counts beyond the
// cap aren't needed, the UI just shows "N+").
std::vector<size_t> findAllPattern(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& pat, const std::vector<bool>& mask,
                                   size_t& totalOut) {
    totalOut = 0;
    // Guard mask.size() too: indexing mask[j] for j < pat.size() is UB on a vector<bool>
    // when the mask is shorter than the pattern (mis-sized rule).
    if (pat.empty() || mask.size() < pat.size() || data.size() < pat.size()) return {};
    SigPattern sp;
    sp.bytes = pat;
    sp.mask.assign(mask.begin(), mask.begin() + pat.size());
    std::vector<size_t> hits = FindAllMasked(data.data(), data.size(), sp, kMaxPatternHits);
    totalOut = hits.size();
    return hits;
}

struct ApiRule { const char* category; const char* label; std::vector<const char*> keys; float base; };

// Imported-API technique groups. Keys are lowercase substrings matched against
// import names (so A/W/Ex suffixes and a few Nt/Zw variants all hit).
const ApiRule kApiRules[] = {
    { "anti-debug", "Anti-debugging checks",
      { "isdebuggerpresent", "checkremotedebugger", "ntqueryinformationprocess",
        "ntsetinformationthread", "outputdebugstring", "debugactiveprocess", "ntquerysysteminformation" }, 0.66f },
    { "crypto", "Cryptographic API",
      { "cryptacquirecontext", "cryptencrypt", "cryptdecrypt", "cryptgenkey", "cryptderivekey",
        "bcryptencrypt", "bcryptdecrypt", "bcryptgeneratesymmetrickey", "cryptstringtobinary" }, 0.7f },
    { "injection", "Process injection / hooking",
      { "virtualallocex", "writeprocessmemory", "createremotethread", "ntcreatethreadex", "rtlcreateuserthread",
        "queueuserapc", "setwindowshookex", "ntmapviewofsection", "ntunmapviewofsection" }, 0.74f },
    { "dynamic", "Dynamic API resolution",
      { "loadlibrary", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress", "getmodulehandle" }, 0.55f },
    { "spawn", "Process / command execution",
      { "createprocess", "shellexecute", "winexec", "createprocessinternal", "ntcreateuserprocess" }, 0.6f },
};

struct PatRule { const char* category; const char* label; std::vector<uint8_t> bytes; std::vector<bool> mask; const char* note; };

// Build a byte/mask pattern from a "48 89 ?? 24" style string.
void mk(std::vector<uint8_t>& b, std::vector<bool>& m, std::initializer_list<int> vals) {
    for (int v : vals) { if (v < 0) { b.push_back(0); m.push_back(false); } else { b.push_back((uint8_t)v); m.push_back(true); } }
}

} // namespace

std::vector<Capability> ScanCapabilities(
    const BinaryFile& bin, const std::function<bool()>& cancelled) {
    std::vector<Capability> out;
    if (!bin.loaded()) return out;
    const auto stopped = [&] { return cancelled && cancelled(); };

    // ---- 1) Imported-API grouping ----
    const auto& imports = bin.imports();
    for (const auto& rule : kApiRules) {
        if (stopped()) return {};
        std::vector<std::string> hits;
        uint64_t addr = 0;
        bool addrValid = false;
        for (const auto& im : imports) {
            std::string ln = lower(im.name);
            for (const char* k : rule.keys) {
                if (ln.find(k) != std::string::npos) {
                    if (std::find(hits.begin(), hits.end(), im.name) == hits.end()) hits.push_back(im.name);
                    if (!addrValid && im.addressKnown) {
                        addr = im.iatVA;
                        addrValid = true;
                    }
                    break;
                }
            }
        }
        if (hits.empty()) continue;
        Capability c;
        c.name = rule.label;
        c.category = rule.category;
        c.confidence = std::min(0.96f, rule.base + 0.07f * (float)(hits.size() - 1));
        c.address = addr;
        c.addressValid = addrValid;
        c.detail = "Imports: ";
        for (size_t i = 0; i < hits.size() && i < 12; ++i) { if (i) c.detail += ", "; c.detail += hits[i]; }
        if (hits.size() > 12) c.detail += ", ...";
        out.push_back(std::move(c));
    }

    // Networking is classified by the shared exact DLL-aware catalog. Substring
    // matching here used to turn USER32!SendMessageW into socket evidence merely
    // because the name contains "send".
    {
        std::vector<std::string> hits;
        NetworkStageMask stages = 0;
        uint64_t address = 0;
        bool addressValid = false;
        for (const auto& import : imports) {
            const auto match = LookupNetworkApi(import.dll, import.name);
            if (!match) continue;
            const std::string display = match->dll + "!" + match->canonicalName +
                                        " (" + NetworkStageText(match->stage) + ")";
            if (std::find(hits.begin(), hits.end(), display) == hits.end())
                hits.push_back(display);
            stages |= NetworkStageBit(match->stage);
            if (!addressValid && import.addressKnown) {
                address = import.iatVA;
                addressValid = true;
            }
        }
        if (!hits.empty()) {
            unsigned stageCount = 0;
            for (unsigned i = 0; i < static_cast<unsigned>(NetworkStage::Count); ++i)
                if (stages & NetworkStageBit(static_cast<NetworkStage>(i))) ++stageCount;
            Capability capability;
            capability.name = "Network I/O";
            capability.category = "network";
            capability.confidence = std::min(0.96f,
                0.62f + 0.07f * static_cast<float>(hits.size() - 1) +
                0.03f * static_cast<float>(stageCount > 0 ? stageCount - 1 : 0));
            capability.address = address;
            capability.addressValid = addressValid;
            capability.detail = "Exact imports: ";
            for (size_t i = 0; i < hits.size() && i < 12; ++i) {
                if (i) capability.detail += ", ";
                capability.detail += hits[i];
            }
            if (hits.size() > 12) capability.detail += ", ...";
            out.push_back(std::move(capability));
        }
    }

    // ---- 2) Packer / protector section names ----
    struct Pk { const char* sec; const char* name; };
    static const Pk kPackers[] = {
        { "UPX0", "UPX" }, { "UPX1", "UPX" }, { "UPX2", "UPX" },
        { ".vmp0", "VMProtect" }, { ".vmp1", "VMProtect" },
        { ".themida", "Themida/WinLicense" }, { ".winlice", "Themida/WinLicense" },
        { ".aspack", "ASPack" }, { ".adata", "ASPack" },
        { ".petite", "Petite" }, { ".nsp0", "NsPack" }, { ".nsp1", "NsPack" },
        { ".enigma1", "Enigma" }, { ".enigma2", "Enigma" }, { ".mpress1", "MPRESS" }, { ".mpress2", "MPRESS" },
        { ".boom", "BoxedApp" }, { ".perplex", "Perplex" },
    };
    std::vector<std::string> packerSecs;
    std::string packerName;
    uint64_t packerAddr = 0;
    bool packerAddrValid = false;
    for (const auto& s : bin.sections())
        for (const auto& pk : kPackers)
            if (stopped()) return {};
            else
            if (s.name == pk.sec) {
                packerSecs.push_back(s.name);
                packerName = pk.name;
                if (!packerAddrValid) {
                    if (CheckedAddressAdd(bin.imageBase(), s.virtualAddress,
                                          packerAddr)) {
                        packerAddrValid = true;
                    }
                }
            }
    if (!packerSecs.empty()) {
        Capability c;
        c.name = packerName + " packer";
        c.category = "packer";
        c.confidence = 0.8f;
        c.address = packerAddr;
        c.addressValid = packerAddrValid;
        c.detail = "Section names: ";
        for (size_t i = 0; i < packerSecs.size(); ++i) { if (i) c.detail += ", "; c.detail += packerSecs[i]; }
        c.detail += " (image may be packed/protected)";
        out.push_back(std::move(c));
    }

    // ---- 3) Distinctive byte patterns ----
    const auto& d = bin.bytes();
    struct Found { const char* name; const char* cat; float conf; const char* note;
                   std::vector<size_t> offs; size_t total; };
    std::vector<Found> found;

    // Collect every (bounded) hit of `b`/`m`; record the capability only if >=1.
    auto scanPat = [&](const char* name, const char* cat, float conf, const char* note,
                       const std::vector<uint8_t>& b, const std::vector<bool>& m) {
        if (stopped()) return;
        size_t total = 0;
        std::vector<size_t> offs = findAllPattern(d, b, m, total);
        if (!offs.empty()) found.push_back({ name, cat, conf, note, std::move(offs), total });
    };

    {   // Direct syscall stub: mov r10,rcx ; mov eax,imm32 ; syscall
        std::vector<uint8_t> b; std::vector<bool> m;
        mk(b, m, { 0x4C,0x8B,0xD1, 0xB8,-1,-1,-1,-1, 0x0F,0x05 });
        scanPat("Direct syscall stub", "evasion", 0.78f,
                "mov r10, rcx / mov eax, imm / syscall (ntdll-less syscall)", b, m);
    }
    // NOTE: crypto constant signatures (AES S-box, SHA-256, MD5, CRC32, TEA, ChaCha, and
    // Base64 alphabets) moved to Core/AlgoScan.h (ScanAlgorithms) - section-aware,
    // orientation-variant (BE/LE), and extent-mapped to the referencing function. The
    // Binary Tech tab merges those results into this list (see BinaryTechTab::runTechScan).
    for (const auto& f : found) {
        if (stopped()) return {};
        Capability c;
        c.name = f.name; c.category = f.cat; c.confidence = f.conf;
        c.hitCount = f.total;
        c.addresses.reserve(f.offs.size());
        size_t unmappedHits = 0;
        for (size_t off : f.offs) {
            uint64_t va = 0;
            if (bin.offsetToVA(off, va)) c.addresses.push_back(va);
            else ++unmappedHits;
        }
        c.address = c.addresses.empty() ? 0 : c.addresses.front();
        c.addressValid = !c.addresses.empty();
        c.detail = f.note;
        // Surface the occurrence count in the human-readable evidence: more hits
        // of a crypto table / syscall stub = stronger evidence (and a "+" when the
        // collection cap was reached so the listing isn't silently truncated).
        if (f.total > 1) {
            char tail[48];
            std::snprintf(tail, sizeof(tail), " (%zu%s occurrences)",
                          f.total, (f.total >= kMaxPatternHits ? "+" : ""));
            c.detail += tail;
        }
        if (unmappedHits) {
            c.detail += " (" + std::to_string(unmappedHits) +
                        " collected hit(s) are file-only/unmapped and are not navigable)";
        }
        out.push_back(std::move(c));
    }

    // Provenance: everything above came from TechScan's own rules.
    for (auto& c : out) c.analyzer = "TechScan";

    // ---- 4) Java launcher / embedded JAR (JavaScan) ----
    {
        if (stopped()) return {};
        JavaScanResult jr = ScanJava(bin);
        if (jr.kind != JavaWrapKind::None) {
            Capability c;
            c.name       = std::string("Java launcher: ") + JavaWrapKindName(jr.kind);
            c.category   = "java";
            c.confidence = jr.confidence;
            c.address    = 0;   // the appended archive is overlay data: it has no VA
            c.addressValid = false;
            c.detail     = jr.detail;
            c.analyzer   = "JavaScan";
            out.push_back(std::move(c));
        }

        // ---- 5) Multi-runtime wrapper/container detection (RuntimeScan) ----
        // Reuses the JavaScan result already computed above. Its mirrored Java
        // finding (analyzer "JavaScan") is skipped: the merge above covers it.
        RuntimeScanResult rr = ScanRuntimes(bin, jr);
        for (auto& f : rr.findings) {
            if (stopped()) return {};
            if (f.analyzer == "JavaScan") continue;
            Capability c;
            c.name       = f.title;
            c.category   = f.category;
            c.confidence = f.confidence;
            c.address    = f.address;
            c.addressValid = f.addressValid;
            c.detail     = f.detail;
            c.analyzer   = f.analyzer;
            out.push_back(std::move(c));
        }
    }

    std::sort(out.begin(), out.end(), [](const Capability& a, const Capability& b) { return a.confidence > b.confidence; });
    return out;
}

} // namespace ds
