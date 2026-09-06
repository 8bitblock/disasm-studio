#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

// Unified analyzer finding (additions.md): every finding carries confidence, evidence,
// and the analyzer that produced it — guesses are never presented as facts.
struct FindingEvidence {
    std::string what;          // e.g. "import: mscoree.dll!_CorExeMain", "string \"electron.asar\" at file offset 0x1234"
    uint64_t    va = 0;        // VA 0 is valid when vaValid is true
    uint64_t    fileOffset = (uint64_t)-1;  // -1 = no file offset
    bool        vaValid = false;
};

struct Finding {
    std::string analyzer;      // source analyzer, e.g. "RuntimeScan"
    std::string title;         // ".NET / CLR runtime", "Electron/Node runtime", ...
    std::string category;      // "runtime" | "container" | "packed"
    float       confidence = 0.f;   // 0..1
    std::string detail;        // one-line human-readable evidence summary
    std::vector<FindingEvidence> evidence;
    uint64_t    address = 0;   // representative VA (VA 0 is valid)
    bool        addressValid = false;
};

} // namespace ds
