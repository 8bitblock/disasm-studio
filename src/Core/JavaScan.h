#pragma once
//
// JavaScan.h
// Java launcher / embedded-JAR detection over a loaded binary. Java EXEs
// (launch4j, jpackage, exe4j, JSmooth, WinRun4J, ...) are native PE stubs that
// append the application JAR to the file as overlay data and bootstrap
// jvm.dll. This module detects the wrapper kind, locates the appended
// ZIP/JAR (EOCD + central-directory math, Authenticode-cert aware), lists its
// entries, and best-effort extracts Main-Class from a STORED manifest.
//
// Pure logic over BinaryFile bytes (no Windows headers). STORED and DEFLATE
// entry extraction is supported via the hand-rolled Core/Inflate decoder
// (ExtractZipEntry); the cheap ScanJava pass itself still reads Main-Class
// from a STORED manifest only. Unit-testable with synthetic PEs/ZIPs.
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;

enum class JavaWrapKind { None, ZipOverlay, JarOverlay, Launch4j, Exe4j, Jpackage, JSmooth, WinRun4J, JvmHost };

// Human-readable name for a wrapper kind ("launch4j", "embedded JAR", ...).
const char* JavaWrapKindName(JavaWrapKind k);

// One central-directory entry of the appended archive (bounded subset).
struct JavaZipEntry {
    std::string name;          // path inside the archive (capped length)
    uint64_t    localHdrOff = 0; // CD-recorded local-header offset, RELATIVE to the zip base
    uint32_t    compSize    = 0;
    uint32_t    uncompSize  = 0;
    uint16_t    method      = 0; // 0 = stored, 8 = deflate
};

struct JavaScanResult {
    JavaWrapKind kind       = JavaWrapKind::None;
    float        confidence = 0.0f;   // 0..1, ladder documented in ScanJava
    std::string  detail;              // human-readable evidence
    uint64_t     jarOffset  = 0;      // file offset of the embedded archive (0 when none)
    uint64_t     jarSize    = 0;      // bytes to carve (cert-trimmed); 0 = no archive
    bool         isJar      = false;  // archive contains META-INF/MANIFEST.MF
    std::string  mainClass;           // best-effort (stored manifest only), may be empty
    std::vector<JavaZipEntry> entries; // central-directory listing, capped (~4096)
};

// Detect a Java wrapper / embedded archive in the loaded image. Returns
// kind == None (confidence 0) for a non-Java binary -- no fabricated results.
JavaScanResult ScanJava(const BinaryFile& bin);

// ---- lower-level helpers, exposed for unit tests ----------------------------

// ZIP end-of-central-directory record, located by FindZipEOCD.
struct ZipEOCD {
    uint64_t eocdPos    = 0;   // position of the PK\x05\x06 signature in [data,data+n)
    uint32_t cdSize     = 0;   // central directory size in bytes
    uint32_t cdOffset   = 0;   // CD offset as recorded (relative to the zip base)
    uint16_t entryCount = 0;   // total entries
    uint16_t commentLen = 0;
};

// Scan the last min(n, 65557) bytes of [data, data+n) for a ZIP EOCD record
// (honours up-to-64KB zip comments; prefers a candidate whose comment length
// reaches the buffer end exactly). Returns false if none found.
bool FindZipEOCD(const uint8_t* data, size_t n, ZipEOCD& out);

// Walk central-directory headers (PK\x01\x02) at absolute position `cdPos`
// (= zipBase + eocd.cdOffset), spanning `cdSize` bytes, into `out` (capped at
// maxEntries). 64-bit wrap-proof; stops at the first malformed header.
// Returns false when the directory doesn't start with a valid CD signature.
bool ParseZipCentralDir(const uint8_t* data, size_t n, uint64_t cdPos, uint64_t cdSize,
                        std::vector<JavaZipEntry>& out, size_t maxEntries = 4096);

// Extract a single archive entry's decompressed bytes. data/n = the WHOLE containing file,
// zipBase = file offset of the zip start (JavaScanResult::jarOffset). Reads name/extra lengths
// from the LOCAL header (they may differ from the central directory), sizes from the central
// directory entry (local sizes may be zeroed with a trailing data descriptor).
// STORED and DEFLATE entries only; returns false (optionally with *err set) otherwise.
bool ExtractZipEntry(const uint8_t* data, size_t n, uint64_t zipBase, const JavaZipEntry& e,
                     std::vector<uint8_t>& out, std::string* err = nullptr);

} // namespace ds
