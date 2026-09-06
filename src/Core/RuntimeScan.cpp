#include "RuntimeScan.h"
#include "AddressSpan.h"
#include "SigMatch.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace ds {

double ShannonEntropy(const uint8_t* p, size_t n) {
    if (!p || !n) return 0.0;
    size_t hist[256] = {};
    for (size_t i = 0; i < n; ++i) ++hist[p[i]];
    double h = 0.0;
    const double inv = 1.0 / (double)n;
    for (size_t b = 0; b < 256; ++b) {
        if (!hist[b]) continue;
        const double pr = (double)hist[b] * inv;
        h -= pr * std::log2(pr);
    }
    return h;
}

namespace {

std::string lower(std::string s) { for (char& c : s) c = (char)std::tolower((unsigned char)c); return s; }

std::string hexs(uint64_t v) { char b[24]; std::snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v); return b; }

// Mirrors JavaWrapKindName (JavaScan.cpp) so RuntimeScan links without JavaScan's
// TU — the test harness builds this file standalone; JavaScanResult is pure data.
const char* javaKindName(JavaWrapKind k) {
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

SigPattern exactPat(const uint8_t* s, size_t len) {
    SigPattern p;
    p.bytes.assign(s, s + len);
    p.mask.assign(len, true);
    return p;
}

// First hit POSITION of an exact byte string via the shared masked BMH matcher
// (all-concrete mask, same shape as JavaScan's containsBytes), SIZE_MAX if
// absent — evidence wants file offsets, not bools.
size_t findStr(const uint8_t* d, size_t n, const char* s) {
    const size_t len = std::strlen(s);
    if (!len || n < len) return SIZE_MAX;
    return FindFirstMasked(d, n, exactPat(reinterpret_cast<const uint8_t*>(s), len));
}

std::string joinWhats(const std::vector<FindingEvidence>& ev) {
    std::string s;
    for (const auto& e : ev) { if (!s.empty()) s += ", "; s += e.what; }
    return s;
}

Finding mk(std::string title, const char* category, float conf, std::string detail,
           std::vector<FindingEvidence> ev, const char* analyzer = "RuntimeScan") {
    Finding f;
    f.analyzer   = analyzer;
    f.title      = std::move(title);
    f.category   = category;
    f.confidence = conf;
    f.detail     = std::move(detail);
    f.evidence   = std::move(ev);
    for (const auto& e : f.evidence) if (e.vaValid) {
        f.address = e.va;
        f.addressValid = true;
        break;
    }
    return f;
}

struct Scan {
    const BinaryFile& bin;
    const uint8_t*    p;
    size_t            n;

    FindingEvidence evAtOffset(std::string what, uint64_t off) const {
        FindingEvidence e;
        e.what       = std::move(what);
        e.fileOffset = off;
        uint64_t va  = 0;
        if (bin.offsetToVA(off, va)) { e.va = va; e.vaValid = true; }
        return e;
    }
    bool strEvidence(const char* s, std::vector<FindingEvidence>& ev) const {
        const size_t pos = findStr(p, n, s);
        if (pos == SIZE_MAX) return false;
        ev.push_back(evAtOffset(std::string("string \"") + s + "\" at file offset " + hexs(pos), pos));
        return true;
    }
    bool importEvidence(const char* dll, std::vector<FindingEvidence>& ev) const {
        const std::string want = lower(dll);
        for (const auto& im : bin.imports()) {
            if (lower(im.dll) != want) continue;
            FindingEvidence e;
            e.what = "import: " + im.dll + "!" + im.name;
            if (im.addressKnown) {
                e.va = im.iatVA;
                e.vaValid = true;
            }
            ev.push_back(std::move(e));
            return true;
        }
        return false;
    }
    // Import first (richer evidence), string fallback — one signal either way.
    bool keyEvidence(const char* key, std::vector<FindingEvidence>& ev) const {
        return importEvidence(key, ev) || strEvidence(key, ev);
    }
};

} // namespace

RuntimeScanResult ScanRuntimes(const BinaryFile& bin, const JavaScanResult& java) {
    RuntimeScanResult r;
    if (!bin.loaded()) return r;
    const Scan sc{ bin, bin.bytes().data(), bin.bytes().size() };
    const uint8_t* p = sc.p;
    const size_t   n = sc.n;

    // The file IS an archive (zip local header / bare EOCD at offset 0): report
    // detectors as usual but never call it a wrapper — there is no native stub.
    r.isStandaloneArchive = n >= 4 && p[0] == 'P' && p[1] == 'K' &&
                            ((p[2] == 3 && p[3] == 4) || (p[2] == 5 && p[3] == 6));

    // ---- .NET / CLR. Ladder: data directory [14] is definitional (0.97) >
    // mscoree.dll!_Cor*Main import without the directory (0.9) > a bare "BSJB"
    // metadata magic anywhere (0.5, heuristic).
    {
        std::vector<FindingEvidence> ev;
        if (bin.clrDirRVA()) {
            FindingEvidence e;
            e.what = "PE data directory [14] (CLR descriptor) at RVA " + hexs(bin.clrDirRVA())
                   + ", size " + std::to_string(bin.clrDirSize());
            uint64_t off = 0;
            uint64_t clrVA = 0;
            if (CheckedAddressAdd(bin.imageBase(), bin.clrDirRVA(), clrVA) &&
                bin.vaToOffset(clrVA, off)) {
                e.va = clrVA;
                e.vaValid = true;
                e.fileOffset = off;
            }
            size_t av = 0;
            const uint8_t* cor = bin.ptrFromRVA(bin.clrDirRVA(), av);
            uint32_t corSize = 0;
            if (cor && av >= sizeof(corSize)) std::memcpy(&corSize, cor, sizeof(corSize));
            const bool validCorHeader = cor && av >= 0x48 &&
                                        bin.clrDirSize() >= 0x48 &&
                                        corSize >= 0x48 && corSize <= av &&
                                        corSize <= bin.clrDirSize();
            if (!validCorHeader) {
                e.what += "; directory is unmapped, truncated, or has an invalid COR20 cb field";
                ev.push_back(std::move(e));
                r.findings.push_back(mk(
                    "Malformed CLR directory", "malformed", 0.35f,
                    "PE data directory [14] is nonzero but does not contain a bounded valid COR20 header; .NET runtime authority was not granted",
                    std::move(ev)));
            } else {
                ev.push_back(std::move(e));
                std::string detail = "PE data directory [14] contains a bounded COR20 header";
                // COR20 header +8 = MetaData directory RVA -> metadata root magic "BSJB".
                uint32_t metaRVA = 0;
                std::memcpy(&metaRVA, cor + 8, 4);
                size_t ma = 0;
                const uint8_t* meta = metaRVA ? bin.ptrFromRVA(metaRVA, ma) : nullptr;
                if (meta && ma >= 4 && std::memcmp(meta, "BSJB", 4) == 0) {
                    FindingEvidence m;
                    m.what = "CLR metadata root magic \"BSJB\" at RVA " + hexs(metaRVA);
                    uint64_t mo = 0;
                    uint64_t metaVA = 0;
                    if (CheckedAddressAdd(bin.imageBase(), metaRVA, metaVA) &&
                        bin.vaToOffset(metaVA, mo)) {
                        m.va = metaVA;
                        m.vaValid = true;
                        m.fileOffset = mo;
                    }
                    ev.push_back(std::move(m));
                    detail += " + BSJB metadata root";
                }
                r.findings.push_back(mk(".NET / CLR runtime", "runtime", 0.97f,
                                        std::move(detail), std::move(ev)));
            }
        } else {
            bool corMain = false;
            for (const auto& im : bin.imports()) {
                if (lower(im.dll) == "mscoree.dll" && (im.name == "_CorExeMain" || im.name == "_CorDllMain")) {
                    FindingEvidence e;
                    e.what = "import: " + im.dll + "!" + im.name;
                    if (im.addressKnown) {
                        e.va = im.iatVA;
                        e.vaValid = true;
                    }
                    ev.push_back(std::move(e));
                    corMain = true;
                    break;
                }
            }
            if (corMain) {
                sc.strEvidence("BSJB", ev);   // corroborating, doesn't change the rung
                r.findings.push_back(mk(".NET / CLR runtime", "runtime", 0.9f,
                                        "mscoree.dll CLR shim import without a CLR data directory",
                                        std::move(ev)));
            } else if (sc.strEvidence("BSJB", ev)) {
                r.findings.push_back(mk(".NET / CLR runtime", "runtime", 0.5f,
                                        "\"BSJB\" metadata magic only, no CLR directory or mscoree import (heuristic)",
                                        std::move(ev)));
            }
        }
    }

    // ---- Java: mirror the already-computed JavaScan verdict (never re-scan).
    if (java.kind != JavaWrapKind::None) {
        std::vector<FindingEvidence> ev;
        if (java.jarSize)
            ev.push_back(sc.evAtOffset("embedded archive at file offset " + hexs(java.jarOffset)
                                       + " (" + std::to_string(java.jarSize) + " bytes)", java.jarOffset));
        if (!java.mainClass.empty()) {
            FindingEvidence e;
            e.what = "Main-Class: " + java.mainClass;
            ev.push_back(std::move(e));
        }
        if (ev.empty()) {
            FindingEvidence e;
            e.what = std::string("wrapper signature: ") + javaKindName(java.kind);
            ev.push_back(std::move(e));
        }
        r.findings.push_back(mk(std::string("Java runtime (") + javaKindName(java.kind) + ")",
                                "runtime", java.confidence, java.detail, std::move(ev), "JavaScan"));
    }

    // ---- Electron / Node: 2+ distinct signals 0.85, exactly 1 a weak 0.55.
    {
        std::vector<FindingEvidence> ev;
        int signals = 0;
        for (const char* s : { "electron.asar", "app.asar", "ELECTRON_RUN_AS_NODE", "v8_context_snapshot" })
            if (sc.strEvidence(s, ev)) ++signals;
        if (sc.importEvidence("node.dll", ev) || sc.importEvidence("libnode.dll", ev) ||
            sc.strEvidence("libnode.dll", ev) || sc.strEvidence("node.dll", ev))
            ++signals;   // the node DLL counts once however it shows up
        if (signals) {
            std::string detail = std::to_string(signals)
                               + (signals == 1 ? " Electron/Node signal: " : " Electron/Node signals: ")
                               + joinWhats(ev);
            if (signals == 1) detail += " (weak: a single string may be incidental)";
            r.findings.push_back(mk("Electron/Node runtime", "runtime",
                                    signals >= 2 ? 0.85f : 0.55f, std::move(detail), std::move(ev)));
        }
    }

    // ---- Unity / Mono: three independent findings.
    {
        auto engine = [&](std::initializer_list<const char*> keys, const char* title, float conf) {
            std::vector<FindingEvidence> ev;
            for (const char* k : keys) sc.keyEvidence(k, ev);
            if (ev.empty()) return;
            std::string detail = joinWhats(ev);
            r.findings.push_back(mk(title, "runtime", conf, std::move(detail), std::move(ev)));
        };
        engine({ "UnityPlayer.dll" },                "Unity engine",  0.85f);
        engine({ "GameAssembly.dll", "il2cpp" },     "Unity IL2CPP",  0.85f);
        engine({ "mono-2.0-bdwgc.dll", "mono.dll" }, "Mono runtime",  0.75f);
    }

    // ---- Python. Ladder: PyInstaller cookie (0.9) > _MEIPASS + pythonXX.dll
    // (0.85) > PYTHONSCRIPT/py2exe (0.8) > a python DLL alone (0.55 — embedding
    // Python does not make the file a wrapper).
    {
        static const uint8_t kPyiCookie[8] = { 0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E };
        const size_t cookiePos = FindFirstMasked(p, n, exactPat(kPyiCookie, sizeof(kPyiCookie)));

        std::vector<FindingEvidence> pyDllEv;   // import-name prefix or a "pythonN[NN].dll" string (regex-free)
        bool pyDll = false;
        for (const auto& im : bin.imports()) {
            const std::string dl = lower(im.dll);
            if (dl.rfind("python3", 0) == 0 || dl.rfind("python2", 0) == 0) {
                FindingEvidence e;
                e.what = "import: " + im.dll + "!" + im.name;
                if (im.addressKnown) {
                    e.va = im.iatVA;
                    e.vaValid = true;
                }
                pyDllEv.push_back(std::move(e));
                pyDll = true;
                break;
            }
        }
        for (const char* prefix : { "python3", "python2" }) {
            if (pyDll) break;
            const size_t plen = std::strlen(prefix);
            if (n < plen) continue;
            const SigPattern pat = exactPat(reinterpret_cast<const uint8_t*>(prefix), plen);
            for (size_t from = 0;;) {
                const size_t pos = FindFirstMasked(p, n, pat, from);
                if (pos == SIZE_MAX) break;
                from = pos + 1;
                size_t k = pos + plen;
                while (k < n && k - (pos + plen) < 2 && p[k] >= '0' && p[k] <= '9') ++k;   // minor digits
                if (k + 4 <= n && std::memcmp(p + k, ".dll", 4) == 0) {
                    std::string name(reinterpret_cast<const char*>(p) + pos, (k + 4) - pos);
                    pyDllEv.push_back(sc.evAtOffset("string \"" + name + "\" at file offset " + hexs(pos), pos));
                    pyDll = true;
                    break;
                }
            }
        }

        const size_t meiPos = findStr(p, n, "_MEIPASS");
        const size_t py2Pos = findStr(p, n, "PYTHONSCRIPT");
        std::vector<FindingEvidence> ev;
        if (cookiePos != SIZE_MAX) {
            ev.push_back(sc.evAtOffset("PyInstaller archive cookie (MEI\\x0c\\x0b\\x0a\\x0b\\x0e) at file offset "
                                       + hexs(cookiePos), cookiePos));
            for (auto& e : pyDllEv) ev.push_back(std::move(e));
            std::string detail = "PyInstaller archive cookie present";
            if (pyDll) detail += " + Python DLL";
            r.findings.push_back(mk("Python (PyInstaller)", "runtime", 0.9f, std::move(detail), std::move(ev)));
        } else if (meiPos != SIZE_MAX && pyDll) {
            ev.push_back(sc.evAtOffset("string \"_MEIPASS\" at file offset " + hexs(meiPos), meiPos));
            for (auto& e : pyDllEv) ev.push_back(std::move(e));
            r.findings.push_back(mk("Python (PyInstaller)", "runtime", 0.85f,
                                    "_MEIPASS bootstrap string + Python DLL", std::move(ev)));
        } else if (py2Pos != SIZE_MAX) {
            ev.push_back(sc.evAtOffset("string \"PYTHONSCRIPT\" at file offset " + hexs(py2Pos), py2Pos));
            for (auto& e : pyDllEv) ev.push_back(std::move(e));
            r.findings.push_back(mk("Python (py2exe)", "runtime", 0.8f,
                                    "PYTHONSCRIPT resource marker", std::move(ev)));
        } else if (pyDll) {
            std::string detail = joinWhats(pyDllEv)
                               + " (embeds Python; may not be a wrapper - a host app linking Python looks the same)";
            r.findings.push_back(mk("Python runtime", "runtime", 0.55f, std::move(detail), std::move(pyDllEv)));
        }
    }

    // ---- Embedded .class blobs: CAFEBABE + plausible version, past offset 0
    // (offset 0 means the file IS a class, not a container) and outside the
    // archive span JavaScan already accounts for. Category "container".
    {
        static const uint8_t kCafe[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
        const SigPattern pat = exactPat(kCafe, sizeof(kCafe));
        std::vector<FindingEvidence> ev;
        size_t kept = 0;
        for (size_t from = 1; kept < 8;) {
            const size_t pos = FindFirstMasked(p, n, pat, from);
            if (pos == SIZE_MAX || pos + 8 > n) break;
            from = pos + 1;
            const unsigned minor = ((unsigned)p[pos + 4] << 8) | p[pos + 5];   // class file: big-endian u2s
            const unsigned major = ((unsigned)p[pos + 6] << 8) | p[pos + 7];
            if (minor > 3 || major < 45 || major > 70) continue;
            if (java.jarSize && pos >= java.jarOffset && pos - java.jarOffset < java.jarSize) continue;
            char w[96];
            std::snprintf(w, sizeof(w), "class magic CAFEBABE (major %u) at file offset 0x%llx",
                          major, (unsigned long long)pos);
            ev.push_back(sc.evAtOffset(w, pos));
            ++kept;
        }
        if (kept) {
            std::string detail = "Embedded Java class file (outside any archive)";
            if (kept > 1) detail += ", x" + std::to_string(kept) + (kept == 8 ? " (capped)" : "");
            r.findings.push_back(mk(kept > 1 ? "Embedded Java class files" : "Embedded Java class file",
                                    "container", 0.6f, std::move(detail), std::move(ev)));
        }
    }

    // ---- Packed / compressed (entropy heuristics). Overlay first — unless the
    // archive JavaScan found already explains the appended data.
    {
        const bool zipExplainsOverlay = java.jarSize != 0 ||
                                        java.kind == JavaWrapKind::ZipOverlay ||
                                        java.kind == JavaWrapKind::JarOverlay;
        if (bin.hasOverlay() && !zipExplainsOverlay) {
            // A trailing Authenticode cert (dir[4] = FILE OFFSET) is signature
            // data, not payload; carve it off like JavaScan does.
            uint64_t end = n;
            const uint64_t so = bin.securityDirOffset(), ss = bin.securityDirSize();
            if (so && so < n && ss && ss <= n && so + ss >= (uint64_t)n) end = so;
            const uint64_t off = bin.overlayOffset();
            if (end > off && end - off >= 4096) {
                const double bits = ShannonEntropy(p + off, (size_t)(end - off));
                if (bits >= 7.5) {
                    char w[128];
                    std::snprintf(w, sizeof(w), "overlay at file offset 0x%llx, %llu bytes, %.2f bits/byte",
                                  (unsigned long long)off, (unsigned long long)(end - off), bits);
                    std::vector<FindingEvidence> ev{ sc.evAtOffset(w, off) };
                    char d[160];
                    std::snprintf(d, sizeof(d),
                                  "overlay entropy %.2f bits/byte over %llu bytes (heuristic; installers and archives also look like this)",
                                  bits, (unsigned long long)(end - off));
                    r.findings.push_back(mk("High-entropy overlay data (possibly packed/compressed)",
                                            "packed", 0.7f, d, std::move(ev)));
                }
            }
        }
        size_t secFindings = 0;
        for (const Section& s : bin.sections()) {
            if (secFindings >= 6) break;
            if (!s.executable && s.name.empty()) continue;
            if (s.rawOffset >= n || s.rawSize < 4096 || s.rawSize > n - s.rawOffset) continue;
            const double bits = ShannonEntropy(p + s.rawOffset, (size_t)s.rawSize);
            if (bits < 7.8) continue;
            FindingEvidence e;
            char w[128];
            std::snprintf(w, sizeof(w), "section %s raw data at file offset 0x%llx, %llu bytes, %.2f bits/byte",
                          s.name.c_str(), (unsigned long long)s.rawOffset,
                          (unsigned long long)s.rawSize, bits);
            e.what       = w;
            e.fileOffset = s.rawOffset;
            uint64_t sectionVA = 0;
            if (bin.offsetToVA(s.rawOffset, sectionVA)) {
                e.va = sectionVA;
                e.vaValid = true;
            }
            char d[160];
            std::snprintf(d, sizeof(d), "entropy %.2f bits/byte (heuristic; compressed resources also look like this)", bits);
            r.findings.push_back(mk("High-entropy section " + s.name, "packed", 0.5f, d, { std::move(e) }));
            ++secFindings;
        }
    }

    std::stable_sort(r.findings.begin(), r.findings.end(),
                     [](const Finding& a, const Finding& b) { return a.confidence > b.confidence; });

    // ---- wrapper verdict: best runtime-handoff finding at >= 0.6. A standalone
    // archive is not a wrapper, whatever the detectors matched inside it.
    if (!r.isStandaloneArchive) {
        for (const Finding& f : r.findings) {
            if (f.category != "runtime" || f.confidence < 0.6f) continue;
            r.wrapperLikely     = true;
            r.wrapperRuntime    = (f.analyzer == "JavaScan")
                                      ? std::string("Java (") + javaKindName(java.kind) + ")"
                                      : f.title;
            r.wrapperConfidence = f.confidence;
            break;   // sorted desc: first qualifying finding is the best one
        }
        if (r.wrapperLikely) {
            for (const Finding& f : r.findings) {
                if (f.category != "runtime") continue;
                if (!r.wrapperDetail.empty()) r.wrapperDetail += "; ";
                r.wrapperDetail += f.detail;
            }
        }
    }
    return r;
}

} // namespace ds
