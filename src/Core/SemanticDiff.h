#pragma once
//
// SemanticDiff.h
// Dependency-light, architecture-neutral semantic binary comparison.
//
// The diff engine consumes immutable, precomputed instruction/CFG facts.  A
// separate BinaryFile adapter (SemanticDiffBinary.h) can build those facts with
// any decoder factory.  Keeping this model pure makes matching deterministic,
// testable, and safe to run on an owned worker without reaching into UI or
// Project state.
//

#include "../Disasm/IDisassembler.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ds {

// Numeric operand components marked as relocations are deliberately ignored by
// the exact semantic fingerprint.  Width, access, registers, scale, and operand
// kind remain significant.  Non-relocation immediates/displacements are retained
// so a constant-only change becomes an instruction edit rather than disappearing.
struct SemanticOperand {
    OperandKind   kind = OperandKind::Invalid;
    OperandAccess access = OperandAccess::None;
    uint16_t      widthBits = 0;

    std::string registerName;
    std::string segmentRegister;
    std::string baseRegister;
    std::string indexRegister;
    int32_t     scale = 0;

    uint64_t immediate = 0;
    bool     immediateSigned = false;
    int64_t  displacement = 0;
    bool     displacementValid = false;
    bool     pcRelative = false;
    bool     valueIsRelocation = false;
};

struct SemanticInstruction {
    uint64_t    address = 0;       // identity/navigation only; never fingerprinted
    uint32_t    length = 0;
    std::string mnemonic;
    std::string display;           // optional UI text; never used for matching
    // Decoder-normalized semantic prefixes are part of opcode identity.  They
    // deliberately remain separate from mnemonic so `rep movsb`, `lock add`,
    // HLE, BND, and NOTRACK cannot alias their unprefixed operations.
    std::vector<InstructionPrefix> prefixes;
    FlowInfo    flow;
    std::vector<SemanticOperand> operands;
    std::vector<std::string> registersRead;
    std::vector<std::string> registersWritten;
    uint64_t    flagsRead = 0;
    uint64_t    flagsWritten = 0;
};

// Convert one decoder Instruction to the immutable diff model.  Direct control-
// flow immediates, PC-relative operands, pointers, and absolute memory addresses
// are tagged relocation-sensitive automatically.
SemanticInstruction MakeSemanticInstruction(const Instruction& instruction);

struct SemanticBasicBlock {
    uint64_t address = 0;
    // Indices into SemanticFunction::instructions, in execution order.
    std::vector<uint32_t> instructionIndices;
    // Successor block addresses.  Addresses may legitimately be zero.
    std::vector<uint64_t> successors;
};

struct SemanticComment {
    uint32_t    instructionIndex = 0;
    std::string text;
};

struct SemanticFunction {
    uint64_t    address = 0;
    uint64_t    size = 0;
    std::string name;
    // Only loader/PDB/analyst-authoritative names participate in the first
    // matching tier.  Heuristic sub_ / guessed names must leave this false.
    bool        authoritativeName = false;
    // Loader/analyst names may be offered for explicit transfer. Generated
    // address labels such as sub_401000 leave this false to avoid proposal spam.
    bool        nameTransferable = false;
    std::string prototype;

    std::vector<SemanticInstruction> instructions;
    std::vector<SemanticBasicBlock> blocks;
    // Direct calls to function entry addresses.  Duplicates are harmless and
    // are canonicalized by the matcher.
    std::vector<uint64_t> callTargets;

    // Optional analyst metadata is read only to produce explicit transfer
    // proposals.  The diff engine has no Project dependency and never applies it.
    std::vector<SemanticComment> comments;
    std::vector<uint32_t> bookmarkInstructions;
};

struct SemanticImage {
    Arch arch = Arch::X64;
    uint64_t contentIdentity = 0;
    std::vector<SemanticFunction> functions;
};

struct SemanticDiffLimits {
    size_t maxFunctions = 10000;
    size_t maxInstructionsPerFunction = 20000;
    size_t maxTotalInstructions = 2000000;
    size_t maxBlocksPerFunction = 10000;
    size_t maxEdgesPerFunction = 50000;
    size_t maxCallsPerFunction = 4096;
    size_t maxOperandsPerInstruction = 16;
    size_t maxEditCellsPerFunction = 1000000; // LCS DP admission bound
    size_t maxHunks = 50000;
    size_t maxTransferProposals = 50000;
    size_t maxBuildBytes = 512u * 1024u * 1024u; // BinaryFile adapter budget
    uint32_t maxNeighborhoodRounds = 4;
};

// Applies non-negotiable allocation/work ceilings.  Callers may lower limits,
// but cannot turn the hostile-input guards into unbounded work by raising them.
SemanticDiffLimits BoundSemanticDiffLimits(const SemanticDiffLimits& requested) noexcept;

enum class SemanticMatchBasis : uint8_t {
    AuthoritativeName,
    SemanticHash,
    CfgStructure,
    CallNeighborhood
};

enum class InstructionEditKind : uint8_t { Insert, Delete, Replace };

struct InstructionEditHunk {
    InstructionEditKind kind = InstructionEditKind::Replace;
    uint32_t leftBegin = 0;
    uint32_t leftCount = 0;
    uint32_t rightBegin = 0;
    uint32_t rightCount = 0;
    bool     leftAddressValid = false;
    uint64_t leftAddress = 0;
    bool     rightAddressValid = false;
    uint64_t rightAddress = 0;
};

struct SemanticFunctionMatch {
    size_t   leftIndex = 0;   // index in the caller-supplied SemanticImage
    size_t   rightIndex = 0;
    uint64_t leftAddress = 0;
    uint64_t rightAddress = 0;
    SemanticMatchBasis basis = SemanticMatchBasis::SemanticHash;
    float    confidence = 0.0f;
    std::string evidence;
    uint64_t leftSemanticHash = 0;
    uint64_t rightSemanticHash = 0;
    uint64_t leftCfgHash = 0;
    uint64_t rightCfgHash = 0;
    std::vector<InstructionEditHunk> hunks;
    bool hunksTruncated = false;
};

struct SemanticUnmatchedFunction {
    size_t index = 0;
    uint64_t address = 0;
    std::string name;
};

enum class MetadataTransferKind : uint8_t { Name, Comment, Prototype, Bookmark };
enum class MetadataTransferDirection : uint8_t { LeftToRight, RightToLeft };

// A proposal is inert data.  Applying one is deliberately a separate UI/user
// action; SemanticDiff never includes or mutates Project.
struct MetadataTransferProposal {
    MetadataTransferKind kind = MetadataTransferKind::Name;
    MetadataTransferDirection direction = MetadataTransferDirection::LeftToRight;
    uint64_t sourceFunction = 0;
    uint64_t targetFunction = 0;
    bool     sourceInstructionValid = false;
    uint32_t sourceInstructionIndex = 0;
    bool     targetInstructionValid = false;
    uint32_t targetInstructionIndex = 0;
    std::string value;
    bool requiresExplicitSelection = true;
};

enum class SemanticDiffPhase : uint8_t {
    Idle,
    Indexing,
    AuthoritativeNames,
    SemanticHashes,
    CfgStructure,
    CallNeighborhood,
    InstructionEdits,
    Complete,
    Cancelled,
    Failed
};

struct SemanticDiffProgress {
    SemanticDiffPhase phase = SemanticDiffPhase::Idle;
    uint64_t completed = 0;
    uint64_t total = 0;
};

struct SemanticDiffResult {
    bool complete = false;
    bool cancelled = false;
    bool truncated = false;
    std::string error;
    std::vector<SemanticFunctionMatch> matched;
    std::vector<SemanticUnmatchedFunction> added;
    std::vector<SemanticUnmatchedFunction> removed;
    std::vector<MetadataTransferProposal> transferProposals;
};

using SemanticDiffCancel = std::function<bool()>;
using SemanticDiffProgressCallback = std::function<void(const SemanticDiffProgress&)>;

// Exception boundary for the complete pure comparison.  On cancellation or an
// exception, complete is false and the result explains why; no partial result is
// presented as authoritative.
SemanticDiffResult ComputeSemanticDiff(
    const SemanticImage& left,
    const SemanticImage& right,
    const SemanticDiffLimits& limits = {},
    const SemanticDiffCancel& cancelled = {},
    const SemanticDiffProgressCallback& progress = {}) noexcept;

struct SemanticDiffServiceResult {
    uint64_t requestId = 0;
    SemanticDiffResult diff;
};

struct SemanticDiffServiceStats {
    uint64_t requests = 0;
    uint64_t requestsCoalesced = 0;
    uint64_t resultsDropped = 0;
    uint64_t jobsFailed = 0;
};

// One owned worker with latest-request-wins coalescing.  The caller supplies
// immutable shared images, so request() does no whole-image copy on the render
// thread.  A superseding request cancels the in-flight comparison.
class SemanticDiffService {
public:
    SemanticDiffService();
    ~SemanticDiffService();
    SemanticDiffService(const SemanticDiffService&) = delete;
    SemanticDiffService& operator=(const SemanticDiffService&) = delete;

    uint64_t request(std::shared_ptr<const SemanticImage> left,
                     std::shared_ptr<const SemanticImage> right,
                     SemanticDiffLimits limits = {});
    void cancel();
    void cancelAndWaitIdle();
    bool tryTakeResult(SemanticDiffServiceResult& result);
    SemanticDiffProgress progress() const;
    SemanticDiffServiceStats stats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ds
