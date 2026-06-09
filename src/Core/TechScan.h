#pragma once
//
// TechScan.h
// Real capability/technique detection over a loaded binary: imported-API
// grouping (anti-debug / network / crypto / injection / dynamic-API / spawn),
// packer section-name signatures, and distinctive byte patterns (direct syscall
// stub, AES S-box, SHA-256 constants). Pure logic over BinaryFile so it is
// unit-testable; the Binary Tech tab renders the result.
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;

struct Capability {
    std::string name;
    std::string category;   // crypto / anti-debug / network / packer / injection / dynamic / spawn / evasion
    float       confidence = 0.0f;  // 0..1
    uint64_t    address    = 0;     // representative VA (IAT slot or first pattern hit), 0 = none
    std::string detail;             // human-readable evidence (APIs / section / pattern)
    // For byte-pattern capabilities: every VA the pattern was found at, bounded by an
    // internal cap; hitCount == addresses.size() (so it is the capped count, not the
    // uncapped total -- the detail string shows "N+" when the cap was reached). Empty
    // for import/section evidence. address == addresses.front() when set.
    std::vector<uint64_t> addresses;
    size_t                hitCount = 0;
};

// Detect capabilities in the loaded image. Returns an empty list for a clean /
// trivial binary (no fabricated results). Sorted by descending confidence.
std::vector<Capability> ScanCapabilities(const BinaryFile& bin);

} // namespace ds
