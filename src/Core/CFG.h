#pragma once
//
// CFG.h
// Builds a control-flow graph (basic blocks + edges) for a function by
// analyzing a disassembled instruction window. Engine-agnostic via IDisassembler.
//
#include "../Disasm/IDisassembler.h"
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace ds {

// ABI selector shared by the decompiler/data-flow entry points. Auto preserves
// legacy behavior (x86 stack args, Win64 register args); exact callers should
// select the ABI that belongs to the loaded image.
enum class DecompileABI : uint8_t {
    Auto,
    Unknown,
    X86Cdecl,
    X86Stdcall,
    Win64,
    SysV64
};

struct BasicBlock {
    struct SwitchCase {
        int64_t  value = 0;
        uint64_t target = 0;
        bool     targetValid = false;
    };
    uint64_t              start = 0;     // first instruction VA
    uint64_t              end   = 0;     // one past last byte; saturates at UINT64_MAX
    std::vector<Instruction> insns;
    // Index of the control-transfer instruction. Usually the final instruction,
    // but architectures such as MIPS execute one or more delay-slot instructions
    // after it; those slots remain owned by this block.
    size_t                transferIndex = (std::numeric_limits<size_t>::max)();
    std::vector<size_t>   succ;          // successor block indices
    bool                  isReturn   = false;
    bool                  isNoReturnCall = false; // analyst-authoritative direct call has no fallthrough
    bool                  isUncond   = false; // ends in unconditional jmp
    bool                  isSwitch   = false; // ends in an indirect jmp resolved to a jump table
    std::vector<uint64_t> caseTargets;       // resolved case target VAs, in table order (switch only)
    // Validity-bearing switch metadata. `caseTargets` remains for source
    // compatibility with existing native jump-table consumers; new code should
    // use switchCases so sparse JVM keys and a target at VA zero are preserved.
    std::vector<SwitchCase> switchCases;
    uint64_t              switchDefaultTarget = 0;
    bool                  switchDefaultTargetValid = false;
};

inline const Instruction& BlockTransferInstruction(const BasicBlock& block) {
    return block.transferIndex < block.insns.size()
         ? block.insns[block.transferIndex] : block.insns.back();
}

// Resolves an indirect jmp (jmp [table + idx*N]) to its case target VAs. The CFG
// is engine/binary-agnostic, so the table read lives behind this callback (the
// UI supplies one backed by the loaded image). A capped result retains its
// incompleteness/evidence so CFG, ownership, pseudocode, and export cannot present
// the first 1,024 entries as a complete switch.
struct ResolvedJumpTable {
    std::vector<uint64_t> targets;
    bool truncated = false;
    std::string evidence;

    ResolvedJumpTable() = default;
    ResolvedJumpTable(std::vector<uint64_t> values)
        : targets(std::move(values)) {}
};
using JumpTableResolver = std::function<ResolvedJumpTable(const Instruction&)>;
using NoreturnCallResolver = std::function<bool(uint64_t directTarget)>;
// Binary-aware consumers can resolve architectural target spellings that are
// not themselves flat VAs (notably x86-16 segment:offset transfers). When this
// callback is absent, the decoder's ordinary direct target is used.
using DirectTargetResolver = std::function<bool(const Instruction&, uint64_t&)>;

// A mapped executable extent belonging to one logical function. Chunks need
// not be adjacent or ordered. Their byte storage only has to remain alive for
// the duration of BuildCFG; decoded instructions are copied into the graph.
struct CFGCodeChunk {
    const uint8_t* data = nullptr;
    size_t         size = 0;
    uint64_t       va = 0;
};

struct ControlFlowGraph {
    uint64_t                 funcStart = 0;
    std::vector<BasicBlock>  blocks;
    // A graph can be useful while still incomplete (decoder failure, address
    // clamp, or instruction budget). Consumers must not silently treat such a
    // graph as proof that an omitted edge/function tail does not exist.
    bool                     complete = true;
    std::string              incompleteReason;
    size_t                   decodedBytes = 0;
    size_t                   decodedInstructions = 0;
};

// Checked address arithmetic for Thumb TBB/TBH. Architectural PC is
// instructionVA+4; the table base is Align(PC,4), while branch targets are
// PC + 2*entry. Split helpers let callers read the entry between the two steps.
bool ThumbTableEntryVA(uint64_t instructionVA, bool halfwordEntries,
                       size_t index, uint64_t& entryVA);
bool ThumbTableTargetVA(uint64_t instructionVA, uint16_t encodedEntry,
                        uint64_t& targetVA);

// Decodes up to maxInsns instructions from the representable part of
// [va, va+size), partitions into basic
// blocks at branch boundaries, and links edges (branch target + fallthrough).
// When `resolveTable` is supplied, indirect jumps are resolved to jump-table case
// targets, marking the block as a switch and linking each case as a successor.
ControlFlowGraph BuildCFG(const uint8_t* code, size_t size, uint64_t va,
                          IDisassembler& dis, size_t maxInsns = 2000,
                          const JumpTableResolver& resolveTable = {},
                          const NoreturnCallResolver& isNoreturnCall = {},
                          const DirectTargetResolver& resolveDirectTarget = {});

// Noncontiguous function equivalent. Fallthrough and delay-slot ownership are
// confined to a single supplied chunk; explicit direct/switch targets may link
// blocks in any other chunk. Missing/undecodable chunks or explicit control-flow
// targets outside the supplied set make `complete` false.
ControlFlowGraph BuildCFG(const std::vector<CFGCodeChunk>& chunks,
                          IDisassembler& dis, size_t maxInsns = 2000,
                          const JumpTableResolver& resolveTable = {},
                          const NoreturnCallResolver& isNoreturnCall = {},
                          const DirectTargetResolver& resolveDirectTarget = {});

} // namespace ds
