#pragma once
//
// FunctionAnalyzer.h
// Discovers function boundaries in a loaded binary using a combination of:
//   - the entry point and PE export table as seeds,
//   - recursive-descent following of direct CALLs,
//   - a prologue heuristic scan over executable sections,
// then estimates each function's size. Engine-agnostic: works through
// IDisassembler so either Zydis or Capstone can drive it.
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;
class IDisassembler;

struct DiscoveredFunction {
    uint64_t    address = 0;
    uint32_t    size    = 0;
    std::string name;       // export name if known, else sub_<addr>
    bool        isExport = false;
};

class FunctionAnalyzer {
public:
    // Returns discovered functions sorted by address. Bounded by maxFunctions
    // and maxInstructions to stay responsive on large images.
    std::vector<DiscoveredFunction>
    analyze(const BinaryFile& bin, IDisassembler& dis,
            size_t maxFunctions = 50000, size_t maxInstrPerFunc = 4000);

    const std::string& lastSummary() const { return summary_; }

private:
    void collectExports(const BinaryFile& bin,
                        std::vector<uint64_t>& seeds,
                        std::vector<std::pair<uint64_t,std::string>>& named);
    void prologueScan(const BinaryFile& bin, std::vector<uint64_t>& seeds);

    std::string summary_;
};

} // namespace ds
