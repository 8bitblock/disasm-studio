#pragma once
//
// CFG.h
// Builds a control-flow graph (basic blocks + edges) for a function by
// analyzing a disassembled instruction window. Engine-agnostic via IDisassembler.
//
#include "../Disasm/IDisassembler.h"
#include <cstdint>
#include <functional>
#include <vector>

namespace ds {

struct BasicBlock {
    uint64_t              start = 0;     // first instruction VA
    uint64_t              end   = 0;     // one past last byte
    std::vector<Instruction> insns;
    std::vector<size_t>   succ;          // successor block indices
    bool                  isReturn   = false;
    bool                  isUncond   = false; // ends in unconditional jmp
    bool                  isSwitch   = false; // ends in an indirect jmp resolved to a jump table
    std::vector<uint64_t> caseTargets;       // resolved case target VAs, in table order (switch only)
};

// Resolves an indirect jmp (jmp [table + idx*N]) to its case target VAs. The CFG
// is engine/binary-agnostic, so the table read lives behind this callback (the
// UI supplies one backed by the loaded image). Return empty if not a jump table.
using JumpTableResolver = std::function<std::vector<uint64_t>(const Instruction&)>;

struct ControlFlowGraph {
    uint64_t                 funcStart = 0;
    std::vector<BasicBlock>  blocks;
};

// Decodes up to maxInsns instructions from [va, va+size), partitions into basic
// blocks at branch boundaries, and links edges (branch target + fallthrough).
// When `resolveTable` is supplied, indirect jumps are resolved to jump-table case
// targets, marking the block as a switch and linking each case as a successor.
ControlFlowGraph BuildCFG(const uint8_t* code, size_t size, uint64_t va,
                          IDisassembler& dis, size_t maxInsns = 2000,
                          const JumpTableResolver& resolveTable = {});

} // namespace ds
