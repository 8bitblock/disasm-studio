#pragma once
//
// RuntimeScan.h
// Multi-runtime container/wrapper detection (additions.md section A): .NET, Java
// (from the already-computed JavaScan result), Electron/Node, Unity/Mono/IL2CPP,
// Python (PyInstaller/py2exe), embedded .class blobs, and packed/compressed
// (high-entropy) overlay or sections.
// Pure logic, no UI deps; never fabricates — empty findings on a clean binary.
//
#include "BinaryFile.h"
#include "Findings.h"
#include "JavaScan.h"

namespace ds {

struct RuntimeScanResult {
    std::vector<Finding> findings;     // sorted by confidence desc
    bool        wrapperLikely = false; // a runtime-handoff finding reached confidence >= 0.6
    std::string wrapperRuntime;        // e.g. "Java (Launch4j)", ".NET / CLR", "Electron"
    float       wrapperConfidence = 0.f;
    std::string wrapperDetail;         // tooltip-ready evidence summary for the banner
    bool        isStandaloneArchive = false; // file IS a zip/jar (PK at offset 0), not a wrapper
};

// Takes the JavaScan result as INPUT (never re-runs ScanJava): the Java finding
// is mirrored from it and its archive span gates the embedded-.class / overlay-
// entropy detectors.
RuntimeScanResult ScanRuntimes(const BinaryFile& bin, const JavaScanResult& java);

double ShannonEntropy(const uint8_t* p, size_t n);   // bits/byte, 0 for n==0; exposed for tests

} // namespace ds
