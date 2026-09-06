//
// AlgoScan.cpp
// Deterministic algorithm / crypto recognizer. See AlgoScan.h for the contract.
//
// Three detectors, all pure:
//   1. Known constant tables / round constants (AES, SHA, MD5, CRC32, TEA, ChaCha)
//      matched as exact byte signatures via SigMatch, in BIG- and LITTLE-endian
//      orientation (word constants land either way depending on whether the source
//      stored a spec-order byte array or an x86 uint32 array).
//   2. A Base64 alphabet classifier (net-new sliding scan): standard, URL-safe, and
//      *mutated* (a permutation of the standard 64-symbol set).
//   3. Extent mapping: each constant hit -> the function(s) that reference it, via a
//      prebuilt XrefIndex + a function list (both optional).
//
// Constant scanning is limited to initialised DATA sections (not whole-image) to cut
// the false positives a code-byte coincidence would cause; a raw blob with no data
// sections falls back to a whole-image scan.
//
#include "AlgoScan.h"
#include "AddressSpan.h"
#include "BinaryFile.h"
#include "SigMatch.h"
#include "XrefIndex.h"
#include "AnalysisJobs.h"   // FuncResult

#include <algorithm>
#include <cstring>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ds {
namespace {

constexpr size_t kMaxHitsPerRule       = 64;        // bound dataVAs per rule
constexpr size_t kMaxRefsPerMatch      = 32;        // bound referencedBy per match
constexpr int    kMaxAlphabetPerSection = 16;       // bound Base64 hits per section
constexpr uint64_t kMaxFuncSpan        = 0x100000;  // 1 MB ref-attribution slack (mirrors UI)

// ---- signature construction helpers -------------------------------------------------

struct Variant { SigPattern pat; std::string note; };  // note appended to detail when non-empty
struct Rule    { std::string name, category; float conf; std::string detail; std::vector<Variant> variants; };

SigPattern exact(std::vector<uint8_t> b) {
    SigPattern p;
    p.mask.assign(b.size(), true);
    p.bytes = std::move(b);
    return p;
}
std::vector<uint8_t> w32be(std::initializer_list<uint32_t> ws) {
    std::vector<uint8_t> b; b.reserve(ws.size() * 4);
    for (uint32_t w : ws) { b.push_back((uint8_t)(w >> 24)); b.push_back((uint8_t)(w >> 16)); b.push_back((uint8_t)(w >> 8)); b.push_back((uint8_t)w); }
    return b;
}
std::vector<uint8_t> w32le(std::initializer_list<uint32_t> ws) {
    std::vector<uint8_t> b; b.reserve(ws.size() * 4);
    for (uint32_t w : ws) { b.push_back((uint8_t)w); b.push_back((uint8_t)(w >> 8)); b.push_back((uint8_t)(w >> 16)); b.push_back((uint8_t)(w >> 24)); }
    return b;
}
std::vector<uint8_t> w64be(std::initializer_list<uint64_t> ws) {
    std::vector<uint8_t> b; b.reserve(ws.size() * 8);
    for (uint64_t w : ws) for (int s = 56; s >= 0; s -= 8) b.push_back((uint8_t)(w >> s));
    return b;
}
std::vector<uint8_t> w64le(std::initializer_list<uint64_t> ws) {
    std::vector<uint8_t> b; b.reserve(ws.size() * 8);
    for (uint64_t w : ws) for (int s = 0; s <= 56; s += 8) b.push_back((uint8_t)(w >> s));
    return b;
}
std::vector<uint8_t> strBytes(const char* s) {
    std::vector<uint8_t> b; for (const char* q = s; *q; ++q) b.push_back((uint8_t)*q); return b;
}

void addByteTable(std::vector<Rule>& v, const char* name, const char* cat, float conf, const char* det, std::vector<uint8_t> bytes) {
    Rule r; r.name = name; r.category = cat; r.conf = conf; r.detail = det;
    r.variants.push_back({ exact(std::move(bytes)), "" });
    v.push_back(std::move(r));
}
void addWord32(std::vector<Rule>& v, const char* name, const char* cat, float conf, const char* det, std::initializer_list<uint32_t> words) {
    Rule r; r.name = name; r.category = cat; r.conf = conf; r.detail = det;
    r.variants.push_back({ exact(w32be(words)), "big-endian" });
    r.variants.push_back({ exact(w32le(words)), "little-endian" });
    v.push_back(std::move(r));
}
void addWord64(std::vector<Rule>& v, const char* name, const char* cat, float conf, const char* det, std::initializer_list<uint64_t> words) {
    Rule r; r.name = name; r.category = cat; r.conf = conf; r.detail = det;
    r.variants.push_back({ exact(w64be(words)), "big-endian" });
    r.variants.push_back({ exact(w64le(words)), "little-endian" });
    v.push_back(std::move(r));
}

// The signature table. Built once. Word constants carry BE+LE variants; byte tables
// and ASCII constants are orientation-free. Hash init constants that MD5 and SHA-1
// share (0x67452301 ...) are deliberately NOT used — each algorithm is keyed on its
// DISTINCTIVE round constants so the two don't alias.
const std::vector<Rule>& rules() {
    static const std::vector<Rule> R = [] {
        std::vector<Rule> v;
        addByteTable(v, "AES Rijndael S-box", "crypto", 0.92f, "Rijndael forward S-box table (AES)",
            { 0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76 });
        addByteTable(v, "AES inverse S-box", "crypto", 0.90f, "Rijndael inverse S-box table (AES decrypt)",
            { 0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB });
        addWord32(v, "AES Te0 round table", "crypto", 0.80f, "AES encryption T-table (Te0 prefix)",
            { 0xC66363A5, 0xF87C7C84 });
        addWord32(v, "AES Td0 round table", "crypto", 0.80f, "AES decryption T-table (Td0 prefix)",
            { 0x51F4A750, 0x5E416553 });
        addWord32(v, "SHA-1 round constants", "hash", 0.85f, "SHA-1 K[0..3] round constants",
            { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 });
        addWord32(v, "SHA-256 K[64]", "hash", 0.90f, "SHA-256 round constants K[0..3]",
            { 0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5 });
        addWord64(v, "SHA-512 K[80]", "hash", 0.90f, "SHA-512 round constants K[0..1]",
            { 0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL });
        addWord32(v, "MD5 T-table", "hash", 0.85f, "MD5 T[1..4] round constants",
            { 0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE });
        addWord32(v, "CRC32 table", "checksum", 0.80f, "CRC-32 (IEEE) lookup table",
            { 0x77073096, 0xEE0E612C, 0x990951BA });
        {   // CRC32 polynomial — short, multi-orientation; lower confidence
            Rule r; r.name = "CRC32 polynomial"; r.category = "checksum"; r.conf = 0.62f;
            r.detail = "CRC-32 reflected/forward polynomial constant";
            r.variants.push_back({ exact(w32be({ 0xEDB88320 })), "reflected (BE)" });
            r.variants.push_back({ exact(w32le({ 0xEDB88320 })), "reflected (LE)" });
            r.variants.push_back({ exact(w32be({ 0x04C11DB7 })), "forward (BE)" });
            r.variants.push_back({ exact(w32le({ 0x04C11DB7 })), "forward (LE)" });
            v.push_back(std::move(r));
        }
        addWord32(v, "TEA/XTEA delta", "crypto", 0.65f,
            "TEA/XTEA golden-ratio delta 0x9E3779B9 (also a generic mixing constant)",
            { 0x9E3779B9 });
        {   // ChaCha / Salsa20 sigma + tau — ASCII, orientation-free
            Rule r; r.name = "ChaCha/Salsa20 constants"; r.category = "crypto"; r.conf = 0.88f;
            r.detail = "ChaCha/Salsa20 sigma/tau constant string";
            r.variants.push_back({ exact(strBytes("expand 32-byte k")), "" });
            r.variants.push_back({ exact(strBytes("expand 16-byte k")), "" });
            v.push_back(std::move(r));
        }
        return v;
    }();
    return R;
}

// ---- Base64 alphabet sets -----------------------------------------------------------

const char* const kB64Std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char* const kB64Url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

struct B64Sets {
    bool std_[256]; bool url_[256];
    B64Sets() {
        std::memset(std_, 0, sizeof(std_)); std::memset(url_, 0, sizeof(url_));
        for (int i = 0; i < 64; ++i) { std_[(uint8_t)kB64Std[i]] = true; url_[(uint8_t)kB64Url[i]] = true; }
    }
};

} // anonymous namespace

std::vector<AlgoMatch> ScanAlgorithms(const BinaryFile& bin,
                                      const XrefIndex* xref,
                                      const std::vector<FuncResult>* functions,
                                      const std::function<bool()>& cancelled) {
    std::vector<AlgoMatch> out;
    if (!bin.loaded()) return out;
    const auto stopped = [&] { return cancelled && cancelled(); };

    const std::vector<Rule>& R = rules();
    static const B64Sets B;

    // Per-rule accumulators (merged across all scanned sections).
    struct Acc { std::vector<uint64_t> vas; std::vector<std::string> orients; std::string section; bool used = false; };
    std::vector<Acc> acc(R.size());

    auto emitAlpha = [&](uint64_t va, const std::string& sec, AlgoKind kind, const char* name,
                         float conf, const char* det, const uint8_t* window, std::string subNote) {
        AlgoMatch m;
        m.name = name; m.category = "encoding"; m.kind = kind; m.confidence = conf;
        m.address = va; m.addressValid = true; m.dataVAs.push_back(va);
        m.section = sec; m.detail = det ? det : "";
        m.alphabet.assign((const char*)window, 64);
        m.substitutionNote = std::move(subNote);
        out.push_back(std::move(m));
    };

    // Scan one contiguous buffer mapped at `baseVA`: accumulate constant hits and emit
    // Base64 alphabet matches.
    auto scanBuf = [&](const uint8_t* p, size_t len, uint64_t baseVA, const std::string& sec) {
        // (1) constant rules
        for (size_t i = 0; i < R.size(); ++i) {
            if (stopped()) return;
            for (const Variant& vrt : R[i].variants) {
                if (stopped()) return;
                if (vrt.pat.empty() || len < vrt.pat.size()) continue;
                std::vector<size_t> offs = FindAllMasked(p, len, vrt.pat, kMaxHitsPerRule);
                for (size_t off : offs) {
                    uint64_t hitVA = 0;
                    if (!CheckedAddressAdd(baseVA, static_cast<uint64_t>(off), hitVA))
                        continue;
                    acc[i].vas.push_back(hitVA);
                    if (!vrt.note.empty()) acc[i].orients.push_back(vrt.note);
                    if (!acc[i].used) { acc[i].section = sec; acc[i].used = true; }
                }
            }
        }
        // (2) Base64 alphabet classifier
        if (len >= 64) {
            int emitted = 0;
            for (size_t i = 0; i + 64 <= len && emitted < kMaxAlphabetPerSection; ) {
                if ((i & 0x3FFFu) == 0 && stopped()) return;
                const uint8_t* w = p + i;
                if (std::memcmp(w, kB64Std, 64) == 0) {
                    uint64_t hitVA = 0;
                    if (CheckedAddressAdd(baseVA, static_cast<uint64_t>(i), hitVA))
                        emitAlpha(hitVA, sec, AlgoKind::AlphabetStd, "Base64 (standard alphabet)", 0.95f,
                                  "Standard Base64 alphabet", w, "");
                    i += 64; ++emitted; continue;
                }
                if (std::memcmp(w, kB64Url, 64) == 0) {
                    uint64_t hitVA = 0;
                    if (CheckedAddressAdd(baseVA, static_cast<uint64_t>(i), hitVA))
                        emitAlpha(hitVA, sec, AlgoKind::AlphabetStd, "Base64 (URL-safe alphabet)", 0.95f,
                                  "URL-safe Base64 alphabet", w, "");
                    i += 64; ++emitted; continue;
                }
                // mutated candidate: all printable + 64 distinct + same symbol SET as std/url
                bool seen[256] = { false }; int distinct = 0; bool printable = true;
                for (int j = 0; j < 64; ++j) {
                    uint8_t b = w[j];
                    if (b < 0x21 || b > 0x7E) { printable = false; break; }
                    if (!seen[b]) { seen[b] = true; ++distinct; }
                }
                if (printable && distinct == 64) {
                    bool inStd = true; for (int j = 0; j < 64; ++j) if (!B.std_[w[j]]) { inStd = false; break; }
                    const char* base = nullptr;
                    if (inStd) base = kB64Std;
                    else { bool inUrl = true; for (int j = 0; j < 64; ++j) if (!B.url_[w[j]]) { inUrl = false; break; } if (inUrl) base = kB64Url; }
                    if (base) {
                        int delta = 0; for (int j = 0; j < 64; ++j) if (w[j] != (uint8_t)base[j]) ++delta;
                        uint64_t hitVA = 0;
                        if (CheckedAddressAdd(baseVA, static_cast<uint64_t>(i), hitVA))
                            emitAlpha(hitVA, sec, AlgoKind::AlphabetMutated, "Base64 (mutated alphabet)", 0.85f,
                                      "Permuted Base64 alphabet (custom symbol order)", w,
                                      std::to_string(delta) + " of 64 positions differ from the " +
                                      (base == kB64Std ? "standard" : "URL-safe") + " alphabet");
                        i += 64; ++emitted; continue;
                    }
                }
                ++i;
            }
        }
    };

    // Prefer initialised, non-executable DATA sections (cuts code-byte false positives).
    bool scannedAny = false;
    for (const Section& s : bin.sections()) {
        if (stopped()) return {};
        if (s.executable || s.rawSize == 0) continue;
        uint64_t va = 0;
        if (!CheckedAddressAdd(bin.imageBase(), s.virtualAddress, va)) continue;
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(va, avail);
        if (!p || avail == 0) continue;
        size_t len = (size_t)std::min<uint64_t>(avail, s.rawSize);
        scanBuf(p, len, va, s.name);
        scannedAny = true;
    }
    // Raw owns one identity-mapped image and can safely scan the whole buffer. A
    // structured image must never turn file offsets (headers/overlay included)
    // into imageBase-relative VAs. If it has no data section, scan only its real
    // file-backed mapped sections, including executable-only images.
    if (!scannedAny) {
        if (bin.format() == BinFormat::Raw) {
            const std::vector<uint8_t>& d = bin.bytes();
            if (!d.empty()) scanBuf(d.data(), d.size(), bin.imageBase(), "image");
        } else {
            for (const Section& s : bin.sections()) {
                if (stopped()) return {};
                if (!s.rawSize) continue;
                uint64_t va = 0;
                if (!CheckedAddressAdd(bin.imageBase(), s.virtualAddress, va)) continue;
                size_t avail = 0;
                const uint8_t* p = bin.ptrFromVA(va, avail);
                if (!p || !avail) continue;
                const size_t len = static_cast<size_t>(
                    std::min<uint64_t>(avail, s.rawSize));
                scanBuf(p, len, va, s.name);
            }
        }
    }

    // Materialise constant matches from the accumulators.
    for (size_t i = 0; i < R.size(); ++i) {
        if (stopped()) return {};
        if (!acc[i].used) continue;
        std::vector<uint64_t>& vas = acc[i].vas;
        std::sort(vas.begin(), vas.end());
        vas.erase(std::unique(vas.begin(), vas.end()), vas.end());
        if (vas.size() > kMaxHitsPerRule) vas.resize(kMaxHitsPerRule);

        AlgoMatch m;
        m.name = R[i].name; m.category = R[i].category; m.kind = AlgoKind::ConstantTable;
        m.confidence = R[i].conf; m.section = acc[i].section;
        m.dataVAs = vas; m.address = vas.empty() ? 0 : vas.front();
        m.addressValid = !vas.empty();

        std::vector<std::string>& o = acc[i].orients;
        std::sort(o.begin(), o.end()); o.erase(std::unique(o.begin(), o.end()), o.end());
        std::string det = R[i].detail;
        if (!o.empty()) {
            det += "  [";
            for (size_t k = 0; k < o.size(); ++k) { if (k) det += ", "; det += o[k]; }
            det += "]";
        }
        if (vas.size() > 1) det += "  (" + std::to_string(vas.size()) + " occurrences)";
        m.detail = std::move(det);
        out.push_back(std::move(m));
    }

    // Extent mapping: constant hit -> referencing function(s).
    if (xref && functions && !functions->empty()) {
        std::vector<std::pair<uint64_t, int>> idx;
        idx.reserve(functions->size());
        for (int i = 0; i < (int)functions->size(); ++i) idx.push_back({ (*functions)[i].address, i });
        std::sort(idx.begin(), idx.end(),
                  [](const std::pair<uint64_t, int>& a, const std::pair<uint64_t, int>& b) { return a.first < b.first; });

        auto containing = [&](uint64_t va) -> const FuncResult* {
            if (idx.empty()) return nullptr;
            auto it = std::upper_bound(idx.begin(), idx.end(), va,
                      [](uint64_t v, const std::pair<uint64_t, int>& e) { return v < e.first; });
            if (it == idx.begin()) return nullptr;
            --it;
            const FuncResult& f = (*functions)[it->second];
            if (va < f.address || va - f.address >= kMaxFuncSpan) return nullptr;
            return &f;
        };

        for (AlgoMatch& m : out) {
            if (stopped()) return {};
            std::vector<AlgoXref> refs;
            std::unordered_set<uint64_t> seenFunc;
            bool seenUnresolved = false;
            for (uint64_t dva : m.dataVAs) {
                const std::vector<uint64_t>* srcs = xref->sources(dva);
                if (!srcs) continue;
                for (uint64_t insn : *srcs) {
                    const FuncResult* f = containing(insn);
                    uint64_t fa = f ? f->address : 0;
                    if (f) {
                        if (!seenFunc.insert(fa).second) continue;
                    } else {
                        if (seenUnresolved) continue;
                        seenUnresolved = true;
                    }
                    AlgoXref x;
                    x.funcAddress = fa;
                    x.funcAddressValid = f != nullptr;
                    x.funcName = f ? f->name : std::string();
                    x.refInsn = insn;
                    x.refInsnValid = true;
                    refs.push_back(std::move(x));
                    if (refs.size() >= kMaxRefsPerMatch) break;
                }
                if (refs.size() >= kMaxRefsPerMatch) break;
            }
            m.referencedBy = std::move(refs);
        }
    }

    // Strongest evidence first; stable tie-break by name for deterministic output/tests.
    std::sort(out.begin(), out.end(), [](const AlgoMatch& a, const AlgoMatch& b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.name < b.name;
    });
    return out;
}

} // namespace ds
