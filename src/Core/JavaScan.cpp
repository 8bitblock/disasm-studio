#include "JavaScan.h"
#include "BinaryFile.h"
#include "Inflate.h"
#include "SigMatch.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace ds {

namespace {

// Bounded little-endian reads over a raw span. Same no-overflow discipline as
// BinaryFile's rd<>: test the two halves separately so `off + size` never wraps.
template <typename T>
T rdp(const uint8_t* d, size_t n, uint64_t off) {
    T v{};
    if (off <= n && sizeof(T) <= n - off) std::memcpy(&v, d + off, sizeof(T));
    return v;
}

constexpr uint32_t kSigEOCD  = 0x06054b50; // PK\x05\x06
constexpr uint32_t kSigCDH   = 0x02014b50; // PK\x01\x02
constexpr uint32_t kSigLocal = 0x04034b50; // PK\x03\x04
constexpr size_t   kMaxNameLen     = 512;     // archive entry-name cap
constexpr size_t   kMaxManifestLen = 64 * 1024;

// Exact byte-string search via the shared masked BMH matcher (all-concrete mask).
bool containsBytes(const uint8_t* d, size_t n, const char* s) {
    SigPattern p;
    const size_t len = std::strlen(s);
    if (!len || n < len) return false;
    p.bytes.assign(reinterpret_cast<const uint8_t*>(s), reinterpret_cast<const uint8_t*>(s) + len);
    p.mask.assign(len, true);
    return FindFirstMasked(d, n, p) != SIZE_MAX;
}

std::string lower(std::string s) { for (char& c : s) c = (char)std::tolower((unsigned char)c); return s; }

// Best-effort Main-Class from a STORED (method 0) MANIFEST.MF: find the
// attribute at a line start and join 72-byte continuation lines (newline +
// single space, per the JAR manifest spec).
std::string parseMainClass(const uint8_t* mf, size_t n) {
    static const char kKey[] = "Main-Class:";
    const size_t keyLen = sizeof(kKey) - 1;
    for (size_t i = 0; i + keyLen <= n; ++i) {
        if (i != 0 && mf[i - 1] != '\n') continue;             // attribute names start a line
        if (std::memcmp(mf + i, kKey, keyLen) != 0) continue;
        std::string v;
        size_t j = i + keyLen;
        while (j < n && mf[j] == ' ') ++j;                     // skip the separating space(s)
        for (;;) {
            while (j < n && mf[j] != '\r' && mf[j] != '\n') {
                if (v.size() >= kMaxNameLen) return v;
                v.push_back((char)mf[j++]);
            }
            while (j < n && (mf[j] == '\r' || mf[j] == '\n')) ++j;
            if (j < n && mf[j] == ' ') { ++j; continue; }      // continuation line
            break;
        }
        while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.pop_back();
        return v;
    }
    return {};
}

} // namespace

const char* JavaWrapKindName(JavaWrapKind k) {
    switch (k) {
        case JavaWrapKind::ZipOverlay: return "appended ZIP";
        case JavaWrapKind::JarOverlay: return "embedded JAR";
        case JavaWrapKind::Launch4j:   return "launch4j";
        case JavaWrapKind::Exe4j:      return "exe4j/install4j";
        case JavaWrapKind::Jpackage:   return "jpackage";
        case JavaWrapKind::JSmooth:    return "JSmooth";
        case JavaWrapKind::WinRun4J:   return "WinRun4J";
        case JavaWrapKind::JvmHost:    return "JVM host";
        default:                       return "none";
    }
}

bool FindZipEOCD(const uint8_t* data, size_t n, ZipEOCD& out) {
    if (!data || n < 22) return false;
    // EOCD = 22 fixed bytes + up to 65535 comment bytes -> search window 65557.
    const size_t window = std::min(n, (size_t)65557);
    const size_t lo = n - window;
    bool haveLoose = false; ZipEOCD loose{};
    for (size_t pos = n - 22 + 1; pos-- > lo; ) {
        if (rdp<uint32_t>(data, n, pos) != kSigEOCD) continue;
        ZipEOCD e;
        e.eocdPos    = pos;
        e.entryCount = rdp<uint16_t>(data, n, pos + 10);
        e.cdSize     = rdp<uint32_t>(data, n, pos + 12);
        e.cdOffset   = rdp<uint32_t>(data, n, pos + 16);
        e.commentLen = rdp<uint16_t>(data, n, pos + 20);
        const uint64_t recEnd = pos + 22ull + e.commentLen;
        if (recEnd == n) { out = e; return true; }            // comment reaches EOF exactly
        if (recEnd < n && !haveLoose) { loose = e; haveLoose = true; } // tolerate trailing junk
    }
    if (haveLoose) { out = loose; return true; }
    return false;
}

bool ParseZipCentralDir(const uint8_t* data, size_t n, uint64_t cdPos, uint64_t cdSize,
                        std::vector<JavaZipEntry>& out, size_t maxEntries) {
    out.clear();
    if (!data || cdPos > n || cdSize > n - cdPos) return false;
    if (cdSize < 46 || rdp<uint32_t>(data, n, cdPos) != kSigCDH) return false;
    uint64_t p = cdPos;
    const uint64_t end = cdPos + cdSize;
    while (p + 46 <= end && out.size() < maxEntries) {
        if (rdp<uint32_t>(data, n, p) != kSigCDH) break;       // malformed -> stop, keep what we have
        JavaZipEntry e;
        e.method      = rdp<uint16_t>(data, n, p + 10);
        e.compSize    = rdp<uint32_t>(data, n, p + 20);
        e.uncompSize  = rdp<uint32_t>(data, n, p + 24);
        const uint16_t nameLen    = rdp<uint16_t>(data, n, p + 28);
        const uint16_t extraLen   = rdp<uint16_t>(data, n, p + 30);
        const uint16_t commentLen = rdp<uint16_t>(data, n, p + 32);
        e.localHdrOff = rdp<uint32_t>(data, n, p + 42);
        const uint64_t nameOff = p + 46;
        if (nameOff > end || nameLen > end - nameOff) break;   // name spills past the CD
        const size_t keep = std::min<size_t>(nameLen, kMaxNameLen);
        e.name.assign(reinterpret_cast<const char*>(data + nameOff), keep);
        out.push_back(std::move(e));
        p = nameOff + (uint64_t)nameLen + extraLen + commentLen;
    }
    return !out.empty();
}

bool ExtractZipEntry(const uint8_t* data, size_t n, uint64_t zipBase, const JavaZipEntry& e,
                     std::vector<uint8_t>& out, std::string* err) {
    out.clear();
    auto fail = [&](const char* m) { if (err) *err = m; return false; };
    constexpr uint64_t kMaxUncomp = (uint64_t)512 << 20;   // 512MB sanity cap
    if (!data) return fail("no data");
    if (e.uncompSize > kMaxUncomp) return fail("entry too large");
    // Name/extra lengths come from the LOCAL header (they may differ from the
    // CD copy); sizes come from the CD entry `e` (local ones may be zeroed
    // with a trailing data descriptor).
    const uint64_t lh = zipBase + e.localHdrOff;
    if (rdp<uint32_t>(data, n, lh) != kSigLocal) return fail("bad local header signature");
    const uint16_t nameLen  = rdp<uint16_t>(data, n, lh + 26);
    const uint16_t extraLen = rdp<uint16_t>(data, n, lh + 28);
    const uint64_t dataOff  = lh + 30ull + nameLen + extraLen;
    if (dataOff > n || e.compSize > n - dataOff) return fail("entry data out of bounds");
    if (e.method == 0) {
        if (e.compSize != e.uncompSize) return fail("stored entry size mismatch");
        out.assign(data + dataOff, data + dataOff + e.compSize);
        return true;
    }
    if (e.method == 8) {
        const size_t cap = (size_t)std::max<uint64_t>(e.uncompSize, 1u << 20) + 64;
        if (!InflateRaw(data + dataOff, e.compSize, out, cap))
            return fail("deflate stream is corrupt");
        if (out.size() != e.uncompSize) return fail("decompressed size mismatch");
        return true;
    }
    if (err) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "unsupported compression method %u", e.method);
        *err = buf;
    }
    return false;
}

JavaScanResult ScanJava(const BinaryFile& bin) {
    JavaScanResult r;
    if (!bin.loaded()) return r;
    const std::vector<uint8_t>& d = bin.bytes();
    const uint8_t* p = d.data();
    const size_t   n = d.size();

    // A trailing Authenticode certificate (security dir [4] -- file offset, not
    // RVA) sits AFTER an appended payload on a signed jar-EXE; exclude it from
    // both the EOCD search window and the carved jarSize.
    uint64_t scanEnd = n;
    {
        const uint64_t so = bin.securityDirOffset(), ss = bin.securityDirSize();
        if (so && so < n && ss && ss <= n && so + ss >= (uint64_t)n) scanEnd = so;
    }

    // ---- 1) locate an appended ZIP/JAR (EOCD -> central directory) ----
    bool zipValid = false;
    ZipEOCD eocd;
    if (FindZipEOCD(p, (size_t)scanEnd, eocd)) {
        const uint64_t cdEnd = (uint64_t)eocd.cdOffset + eocd.cdSize;   // 64-bit: no wrap
        if (cdEnd <= eocd.eocdPos) {
            // Appended-zip base math (load-bearing): the CD offset field is
            // relative to the zip's own start, which for an appended archive is
            // NOT file offset 0. Recover it from where the CD actually ends.
            const uint64_t zipBase = eocd.eocdPos - cdEnd;
            if (ParseZipCentralDir(p, (size_t)scanEnd, zipBase + eocd.cdOffset, eocd.cdSize,
                                   r.entries)) {
                zipValid    = true;
                r.jarOffset = zipBase;
                r.jarSize   = scanEnd - zipBase;
                for (const auto& e : r.entries)
                    if (e.name == "META-INF/MANIFEST.MF") { r.isJar = true; break; }
            }
        }
    }
    // Fallback: a local-header magic right at the PE overlay start but no valid
    // EOCD (truncated / oddball archive) -- report it, low confidence.
    bool truncatedZip = false;
    if (!zipValid && bin.hasOverlay() && bin.overlayOffset() < scanEnd &&
        rdp<uint32_t>(p, (size_t)scanEnd, bin.overlayOffset()) == kSigLocal) {
        truncatedZip = true;
        r.jarOffset  = bin.overlayOffset();
        r.jarSize    = scanEnd - bin.overlayOffset();
    }

    // ---- 2) Main-Class (stored manifest only -- the scan pass stays cheap;
    //         callers needing a DEFLATE manifest go through ExtractZipEntry) ----
    if (r.isJar) {
        for (const auto& e : r.entries) {
            if (e.name != "META-INF/MANIFEST.MF" || e.method != 0) continue;
            const uint64_t lh = r.jarOffset + e.localHdrOff;
            if (rdp<uint32_t>(p, (size_t)scanEnd, lh) != kSigLocal) break;
            const uint16_t nameLen  = rdp<uint16_t>(p, (size_t)scanEnd, lh + 26);
            const uint16_t extraLen = rdp<uint16_t>(p, (size_t)scanEnd, lh + 28);
            const uint64_t dataOff  = lh + 30ull + nameLen + extraLen;
            const uint64_t len      = std::min<uint64_t>(e.uncompSize, kMaxManifestLen);
            if (dataOff <= scanEnd && len <= scanEnd - dataOff)
                r.mainClass = parseMainClass(p + dataOff, (size_t)len);
            break;
        }
    }

    // ---- 3) wrapper signatures (most specific first) ----
    JavaWrapKind sig = JavaWrapKind::None;
    std::string sigEvidence;
    bool jliImport = false, jvmImport = false;
    for (const auto& im : bin.imports()) {
        const std::string dll = lower(im.dll);
        if (dll == "jli.dll") jliImport = true;
        else if (dll == "jvm.dll" || dll == "j9vm.dll") jvmImport = true;
    }
    auto any = [&](std::initializer_list<const char*> keys) {
        for (const char* k : keys) if (containsBytes(p, n, k)) return true;
        return false;
    };
    if      (any({ "launch4j", "Launch4j" }))             { sig = JavaWrapKind::Launch4j; sigEvidence = "launch4j strings"; }
    else if (any({ "exe4j_log", "install4j", "exe4j" }))  { sig = JavaWrapKind::Exe4j;    sigEvidence = "exe4j/install4j strings"; }
    else if (any({ "JSmooth", "jsmooth" }))               { sig = JavaWrapKind::JSmooth;  sigEvidence = "JSmooth strings"; }
    else if (any({ "WinRun4J", "winrun4j" }))             { sig = JavaWrapKind::WinRun4J; sigEvidence = "WinRun4J strings"; }
    else if (any({ "jpackage" }) || jliImport)            { sig = JavaWrapKind::Jpackage; sigEvidence = jliImport ? "jli.dll import" : "jpackage strings"; }
    else if (jvmImport || any({ "JNI_CreateJavaVM" }))    { sig = JavaWrapKind::JvmHost;  sigEvidence = jvmImport ? "jvm.dll import" : "JNI_CreateJavaVM string"; }

    // ---- 4) verdict ladder ----
    char buf[256];
    auto entriesNote = [&]() -> std::string {
        std::snprintf(buf, sizeof(buf), "%zu entr%s", r.entries.size(), r.entries.size() == 1 ? "y" : "ies");
        std::string s = buf;
        if (!r.mainClass.empty()) s += ", Main-Class " + r.mainClass;
        return s;
    };
    if (sig != JavaWrapKind::None && zipValid && r.isJar) {
        r.kind = sig; r.confidence = 0.95f;
        r.detail = std::string(JavaWrapKindName(sig)) + " (" + sigEvidence + ") + appended JAR (" + entriesNote() + ")";
    } else if (sig != JavaWrapKind::None && (zipValid || truncatedZip)) {
        r.kind = sig; r.confidence = truncatedZip ? 0.6f : 0.7f;
        r.detail = std::string(JavaWrapKindName(sig)) + " (" + sigEvidence + ") + appended ZIP"
                 + (zipValid ? " (" + entriesNote() + ", no manifest)" : " (truncated archive)");
    } else if (zipValid && r.isJar) {
        r.kind = JavaWrapKind::JarOverlay; r.confidence = 0.8f;
        r.detail = "appended JAR (" + entriesNote() + ")";
    } else if (sig != JavaWrapKind::None) {
        r.kind = sig; r.confidence = 0.6f;
        r.detail = std::string(JavaWrapKindName(sig)) + " (" + sigEvidence + "), no embedded archive found";
        r.jarOffset = r.jarSize = 0; r.entries.clear();
    } else if (zipValid || truncatedZip) {
        r.kind = JavaWrapKind::ZipOverlay; r.confidence = truncatedZip ? 0.4f : 0.5f;
        r.detail = zipValid ? "appended ZIP, no JAR manifest (could be an SFX/installer archive) ("
                              + entriesNote() + ")"
                            : "appended data starts with a ZIP local header (truncated archive?)";
    } else {
        r.jarOffset = r.jarSize = 0;       // nothing credible -- report a clean None
        r.entries.clear();
    }
    return r;
}

} // namespace ds
