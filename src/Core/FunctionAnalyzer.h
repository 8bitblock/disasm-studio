#pragma once
//
// FunctionAnalyzer.h
// Discovers function boundaries in a loaded binary using a combination of:
//   - the entry point and PE export table as seeds,
//   - recursive-descent following of direct CALLs,
//   - a prologue heuristic scan over executable sections,
// then owns the basic blocks reachable from each start. Engine-agnostic: works
// through IDisassembler so either Zydis or Capstone can drive it.
//
#include "CFG.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ds {

class BinaryFile;
class IDisassembler;
enum class Arch;
struct Instruction;

// An analyst decision overrides inferred/API noreturn proof. `nullopt` means no
// decision, true means the target cannot return, and false explicitly restores
// ordinary returning flow.
using FunctionNoreturnDecisionResolver =
    std::function<std::optional<bool>(uint64_t)>;

// One half-open, instruction-aligned range owned by a function. Chunks are
// sorted, non-empty, and non-overlapping within a function; distinct functions
// may overlap when the binary deliberately exposes overlapping instruction
// streams. A function can therefore have a small entry chunk plus one or more
// separated branch-target chunks without claiming the intervening bytes.
struct FunctionChunk {
    uint64_t address = 0;
    uint32_t size = 0;
};

// Function starts do not all carry the same instruction-boundary authority.
// Loader/analyst roots are exact, a direct call reached from an exact stream is
// reconciled, while byte-pattern/classifier guesses remain display-only until an
// authoritative predecessor proves their boundary.
enum class FunctionSeedKind : uint8_t {
    Loader,
    Entry,
    Symbol,
    Unwind,
    Landmark,
    JavaMethod,
    ReachedCall,
    Classifier,
    Prologue,
    LegacyRawBase,
    Analyst,
    GameMakerCode,
};

enum class FunctionBoundaryConfidence : uint8_t {
    Heuristic,
    Reconciled,
    Authoritative,
};

inline const char* FunctionSeedKindName(FunctionSeedKind kind) {
    switch (kind) {
        case FunctionSeedKind::Loader:        return "loader";
        case FunctionSeedKind::Entry:         return "entry";
        case FunctionSeedKind::Symbol:        return "symbol";
        case FunctionSeedKind::Unwind:        return "unwind";
        case FunctionSeedKind::Landmark:      return "landmark";
        case FunctionSeedKind::JavaMethod:    return "Java method";
        case FunctionSeedKind::ReachedCall:   return "reached call";
        case FunctionSeedKind::Classifier:    return "classifier";
        case FunctionSeedKind::Prologue:      return "prologue heuristic";
        case FunctionSeedKind::LegacyRawBase: return "legacy Raw base";
        case FunctionSeedKind::Analyst:       return "analyst";
        case FunctionSeedKind::GameMakerCode: return "GameMaker code entry";
    }
    return "unknown";
}

inline const char* FunctionBoundaryConfidenceName(FunctionBoundaryConfidence confidence) {
    switch (confidence) {
        case FunctionBoundaryConfidence::Heuristic:     return "heuristic";
        case FunctionBoundaryConfidence::Reconciled:    return "reconciled";
        case FunctionBoundaryConfidence::Authoritative: return "authoritative";
    }
    return "unknown";
}

struct DiscoveredFunction {
    uint64_t    address = 0;
    // Backward-compatible contiguous size. For loader-authoritative extents it
    // remains that exact extent; otherwise it is the entry chunk's size. New
    // ownership-aware consumers should use chunks.
    uint32_t    size    = 0;
    std::string name;       // export name if known, else sub_<addr>
    bool        isExport = false;
    std::vector<FunctionChunk> chunks;
    bool        noreturn = false;          // proven only from authoritative exit imports
    bool        ownershipTruncated = false;
    FunctionSeedKind seedKind = FunctionSeedKind::Prologue;
    FunctionBoundaryConfidence boundaryConfidence = FunctionBoundaryConfidence::Heuristic;
};

class FunctionAnalyzer {
public:
    // Returns discovered functions sorted by address. Bounded by maxFunctions
    // and maxInstructions to stay responsive on large images. This convenience
    // overload accepts only a structured image with a loader-authoritative
    // machine; Raw/Unknown images must use the exact-architecture form below.
    std::vector<DiscoveredFunction>
    analyze(const BinaryFile& bin, IDisassembler& dis,
            size_t maxFunctions = 50000, size_t maxInstrPerFunc = 4000);

    // Exact-architecture form used by the background pipeline. Raw images do
    // not encode a machine in their bytes, so the caller's selected Arch must
    // gate x86/x64 prologue byte-pattern heuristics. The start-at-base seed and
    // recursive call discovery remain architecture-neutral.
    std::vector<DiscoveredFunction>
    analyze(const BinaryFile& bin, IDisassembler& dis, Arch arch,
            size_t maxFunctions = 50000, size_t maxInstrPerFunc = 4000,
            const std::function<bool()>& cancelled = {},
            const std::vector<uint64_t>& supplementalSeeds = {},
            const std::vector<uint64_t>& analystSeeds = {},
            const JumpTableResolver& resolveJumpTable = {},
            const FunctionNoreturnDecisionResolver& noreturnDecision = {});

    const std::string& lastSummary() const { return summary_; }

private:
    void collectExports(const BinaryFile& bin,
                        std::vector<uint64_t>& seeds,
                        std::vector<std::pair<uint64_t,std::string>>& named);
    void prologueScan(const BinaryFile& bin, IDisassembler& dis, Arch arch,
                      const std::vector<std::pair<uint64_t,uint64_t>>& literalSpans,
                      std::vector<uint64_t>& seeds, size_t candidateBudget,
                      const std::function<bool()>& cancelled);

    std::string summary_;
    bool prologueTruncated_ = false;
    bool cancelled_ = false;
    size_t prologueCandidates_ = 0;
    size_t prologueBytesScanned_ = 0;
};

} // namespace ds
