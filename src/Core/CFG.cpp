#include "CFG.h"
#include "AddressSpan.h"
#include "InstructionReference.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <set>
#include <string>
#include <unordered_map>

namespace ds {

bool ThumbTableEntryVA(uint64_t instructionVA, bool halfwordEntries,
                       size_t index, uint64_t& entryVA) {
    if (instructionVA > (std::numeric_limits<uint64_t>::max)() - 4) return false;
    const uint64_t pc = instructionVA + 4;
    const uint64_t tableBase = pc & ~uint64_t{3};
    const uint64_t width = halfwordEntries ? 2u : 1u;
    if (index > ((std::numeric_limits<uint64_t>::max)() - tableBase) / width) return false;
    entryVA = tableBase + static_cast<uint64_t>(index) * width;
    return true;
}

bool ThumbTableTargetVA(uint64_t instructionVA, uint16_t encodedEntry,
                        uint64_t& targetVA) {
    if (instructionVA > (std::numeric_limits<uint64_t>::max)() - 4) return false;
    const uint64_t pc = instructionVA + 4;
    const uint64_t displacement = static_cast<uint64_t>(encodedEntry) * 2u;
    if (displacement > (std::numeric_limits<uint64_t>::max)() - pc) return false;
    targetVA = pc + displacement;
    return true;
}

// A block-ending control transfer: jmp/jcc/ret (but NOT call, which returns).
static bool endsBlock(const Instruction& in) { return InstructionEndsBlock(in); }
static bool isRet(const Instruction& in) {
    // Honor the decoder's own return flag (set for non-x86 returns — blr / jr $ra /
    // bx lr / ... — as well as x86) so those blocks are tagged isReturn and don't get a
    // spurious fallthrough successor; keep the x86 mnemonic checks as a fallback.
    return InstructionIsReturn(in) ||
           (in.flow.kind == FlowKind::None &&
            (in.mnemonic == "ret" || in.mnemonic == "retn" ||
             in.mnemonic == "retf"));
}
static bool isUncondJmp(const Instruction& in) {
    if (InstructionIsUnconditionalBranch(in)) return true;
    return in.mnemonic == "jmp" || in.mnemonic == "jmpq" ||
           in.mnemonic == "goto" || in.mnemonic == "goto_w" || // JVM unconditionals
           in.mnemonic == "b" || in.mnemonic == "b.w" ||       // ARM/Thumb/AArch64
           in.mnemonic == "bx" || in.mnemonic == "br" ||
           in.mnemonic == "tbb" || in.mnemonic == "tbh";
}

// A PE import call is normally encoded as call [rip+disp32] (x64) or
// call [absolute] (x86). The resolver's coordinate is the IAT slot, not the
// pointer stored in it, so it remains useful for static images without rebasing
// or dereferencing mutable process state. Indexed/register-indirect calls remain
// unresolved and can never acquire noreturn semantics by guesswork.
static bool staticCallMemoryTarget(const Instruction& instruction, uint64_t& target) {
    const TypedOperand* memory = nullptr;
    for (const TypedOperand& operand : instruction.typedOperands) {
        if (operand.kind != OperandKind::Memory) continue;
        if (memory) return false;
        memory = &operand;
    }
    return memory && TryGetStaticMemoryAddress(instruction, *memory, target);
}

// Linear decoding deliberately sees bytes beyond a terminator so it can recover
// later branch targets, but those bytes must not survive merely because they form
// valid instructions. Retain only blocks reachable from the function entry (and,
// for chunked functions, each separately owned cold-chunk root), then remap edges.
static void pruneUnreachableBlocks(ControlFlowGraph& graph,
                                   const std::vector<uint64_t>& roots) {
    if (graph.blocks.empty()) return;
    std::unordered_map<uint64_t, size_t> byStart;
    byStart.reserve(graph.blocks.size());
    for (size_t i = 0; i < graph.blocks.size(); ++i)
        byStart[graph.blocks[i].start] = i;
    std::vector<uint8_t> reachable(graph.blocks.size(), 0);
    std::vector<size_t> work;
    for (uint64_t root : roots) {
        auto it = byStart.find(root);
        if (it != byStart.end() && !reachable[it->second]) {
            reachable[it->second] = 1;
            work.push_back(it->second);
        }
    }
    while (!work.empty()) {
        const size_t index = work.back();
        work.pop_back();
        auto admit = [&](size_t successor) {
            if (successor < reachable.size() && !reachable[successor]) {
                reachable[successor] = 1;
                work.push_back(successor);
            }
        };
        for (size_t successor : graph.blocks[index].succ) admit(successor);
        // Historically a supplied decode extent may contain independent blocks
        // after an ordinary return/unconditional transfer (notably JVM exception
        // or verifier-owned regions). Preserve those islands, but never restart
        // after a proven noreturn call: its physical tail is dead unless reached
        // by a real edge from another live block or supplied as a cold chunk root.
        if (!graph.blocks[index].isNoReturnCall) {
            auto physicalNext = byStart.find(graph.blocks[index].end);
            if (physicalNext != byStart.end()) admit(physicalNext->second);
        }
    }
    std::vector<size_t> remap(graph.blocks.size(), (std::numeric_limits<size_t>::max)());
    std::vector<BasicBlock> kept;
    kept.reserve(graph.blocks.size());
    for (size_t i = 0; i < graph.blocks.size(); ++i) {
        if (!reachable[i]) continue;
        remap[i] = kept.size();
        kept.push_back(std::move(graph.blocks[i]));
    }
    for (BasicBlock& block : kept) {
        std::vector<size_t> successors;
        successors.reserve(block.succ.size());
        for (size_t old : block.succ)
            if (old < remap.size() && remap[old] != (std::numeric_limits<size_t>::max)())
                successors.push_back(remap[old]);
        block.succ = std::move(successors);
    }
    graph.blocks = std::move(kept);
}

ControlFlowGraph BuildCFG(const uint8_t* code, size_t size, uint64_t va,
                          IDisassembler& dis, size_t maxInsns,
                          const JumpTableResolver& resolveTable,
                          const NoreturnCallResolver& resolveNoreturnCall,
                          const DirectTargetResolver& resolveDirectTarget) {
    ControlFlowGraph g;
    g.funcStart = va;
    if (!code || !size) return g;
    const size_t requestedSize = size;
    size = ClampAddressableBytes(va, size);
    if (!size) {
        g.complete = false;
        g.incompleteReason = "address range is not representable";
        return g;
    }
    if (size != requestedSize) {
        g.complete = false;
        g.incompleteReason = "address range was clamped";
    }

    // 1. Linear decode of the window.
    std::vector<Instruction> lin;
    size_t off = 0;
    while (off < size && lin.size() < maxInsns) {
        uint64_t atVA = 0;
        if (!CheckedAddressAdd(va, static_cast<uint64_t>(off), atVA)) {
            g.complete = false; g.incompleteReason = "instruction address overflow"; break;
        }
        Instruction in;
        if (!dis.decodeOne(code + off, size - off, atVA, in)) {
            g.complete = false; g.incompleteReason = "decoder stopped before the end of the window"; break;
        }
        if (!in.length || in.length > size - off) {
            g.complete = false; g.incompleteReason = "decoder returned an invalid instruction length"; break;
        }
        // A decoder is required to describe the address it was asked to decode.
        // Normalize here as a final containment boundary for custom/test engines.
        in.address = atVA;
        lin.push_back(in);
        off += in.length;
        // Heuristic stop: once we pass a ret that has no in-range successors we
        // still continue (functions have multiple rets); the maxInsns/size caps.
    }
    if (off < size && lin.size() >= maxInsns) {
        g.complete = false;
        g.incompleteReason = "instruction budget exhausted";
    }
    g.decodedBytes = off;
    g.decodedInstructions = lin.size();
    if (lin.empty()) return g;

    auto directTargetOf = [&](const Instruction& instruction, uint64_t& target) {
        return resolveDirectTarget ? resolveDirectTarget(instruction, target)
                                   : TryGetDirectTarget(instruction, target);
    };
    auto isAnalystNoreturnCall = [&](const Instruction& instruction) {
        if (!resolveNoreturnCall || !InstructionIsCall(instruction)) return false;
        uint64_t target = 0;
        return (directTargetOf(instruction, target) ||
                staticCallMemoryTarget(instruction, target)) &&
               resolveNoreturnCall(target);
    };
    auto blockEnding = [&](const Instruction& instruction) {
        return endsBlock(instruction) || isAnalystNoreturnCall(instruction);
    };

    const size_t decodedBytes = off;

    auto addressAfterDelaySlots = [&](size_t transferIndex, uint64_t& address) {
        size_t finalIndex = transferIndex;
        uint8_t remaining = lin[transferIndex].flow.delaySlots;
        while (remaining && finalIndex + 1 < lin.size()) {
            uint64_t expected = 0;
            if (!CheckedAddressAdd(lin[finalIndex].address, lin[finalIndex].length, expected) ||
                lin[finalIndex + 1].address != expected)
                break;
            ++finalIndex;
            --remaining;
        }
        if (remaining) {
            g.complete = false;
            g.incompleteReason = "a control-transfer delay slot is missing from the decode window";
            return false;
        }
        return CheckedAddressAdd(lin[finalIndex].address, lin[finalIndex].length, address);
    };

    std::unordered_map<uint64_t, size_t> idx;
    for (size_t i = 0; i < lin.size(); ++i) idx[lin[i].address] = i;

    // 1b. Resolve indirect jumps (x86 jmp [table + idx*N], Thumb TBB/TBH)
    // to jump-table case targets.
    // Keyed by the jmp instruction address; only targets that land on a decoded
    // instruction boundary are kept (so each can become its own basic block).
    std::unordered_map<uint64_t, std::vector<uint64_t>> tables;
    if (resolveTable) {
        for (const auto& in : lin) {
            if (!blockEnding(in) || !isUncondJmp(in)) continue;
            uint64_t directTarget = 0;
            if (directTargetOf(in, directTarget)) continue;             // direct jmp: handled normally
            ResolvedJumpTable resolved = resolveTable(in);
            if (resolved.truncated) {
                if (g.complete) {
                    g.incompleteReason = "jump-table recovery reached its entry cap";
                    if (!resolved.evidence.empty())
                        g.incompleteReason += " (" + resolved.evidence + ")";
                }
                g.complete = false;
            }
            std::vector<uint64_t> kept;
            for (uint64_t t : resolved.targets) if (idx.count(t)) kept.push_back(t);
            if (!kept.empty()) tables[in.address] = std::move(kept);
        }
    }

    // 2. Leaders: function start, branch targets, fallthroughs, and switch cases.
    std::set<uint64_t> leaders;
    leaders.insert(va);
    for (size_t instructionIndex = 0; instructionIndex < lin.size(); ++instructionIndex) {
        const Instruction& in = lin[instructionIndex];
        if (!blockEnding(in)) continue;
        uint64_t fall = 0;
        if (!isAnalystNoreturnCall(in) &&
            addressAfterDelaySlots(instructionIndex, fall) &&
            AddressInSpan(va, decodedBytes, fall))
            leaders.insert(fall);
        uint64_t directTarget = 0;
        if (directTargetOf(in, directTarget) &&
            AddressInSpan(va, decodedBytes, directTarget))
            leaders.insert(directTarget);
        if (!in.switchInfo.cases.empty() || in.switchInfo.defaultTargetValid) {
            for (const auto& c : in.switchInfo.cases)
                if (c.targetValid && AddressInSpan(va, decodedBytes, c.target)) leaders.insert(c.target);
            if (in.switchInfo.defaultTargetValid &&
                AddressInSpan(va, decodedBytes, in.switchInfo.defaultTarget))
                leaders.insert(in.switchInfo.defaultTarget);
        } else {
            for (uint64_t t : in.extraTargets)                  // legacy encoded switch cases
                if (AddressInSpan(va, decodedBytes, t)) leaders.insert(t);
        }
    }
    for (const auto& t : tables) for (uint64_t tgt : t.second) leaders.insert(tgt);

    // 3. Build blocks spanning [leader, nextLeader) until a block-ender.
    std::vector<uint64_t> ls(leaders.begin(), leaders.end()); // sorted ascending
    for (size_t li = 0; li < ls.size(); ++li) {
        BasicBlock b;
        b.start = ls[li];
        const bool hasBlockLimit = li + 1 < ls.size();
        const uint64_t blockLimit = hasBlockLimit ? ls[li + 1] : 0;
        auto it = idx.find(b.start);
        if (it == idx.end()) continue;
        size_t k = it->second;
        while (k < lin.size() && (!hasBlockLimit || lin[k].address < blockLimit)) {
            b.insns.push_back(lin[k]);
            if (blockEnding(lin[k])) {
                b.transferIndex = b.insns.size() - 1;
                uint8_t remaining = lin[k].flow.delaySlots;
                while (remaining && k + 1 < lin.size()) {
                    uint64_t expected = 0;
                    if (!CheckedAddressAdd(lin[k].address, lin[k].length, expected) ||
                        lin[k + 1].address != expected)
                        break;
                    ++k;
                    b.insns.push_back(lin[k]);
                    --remaining;
                }
                if (remaining) {
                    g.complete = false;
                    g.incompleteReason = "a control-transfer delay slot is missing from the decode window";
                }
                ++k;
                break;
            }
            ++k;
        }
        if (b.insns.empty()) continue;
        b.end = SaturatingAddressAdd(b.insns.back().address, b.insns.back().length);
        g.blocks.push_back(std::move(b));
    }

    std::unordered_map<uint64_t, size_t> blockOf;
    for (size_t i = 0; i < g.blocks.size(); ++i) blockOf[g.blocks[i].start] = i;

    // 4. Edges from each block's terminator.
    for (auto& b : g.blocks) {
        if (b.insns.empty()) continue;
        const Instruction& transfer = BlockTransferInstruction(b);
        if (b.transferIndex >= b.insns.size()) {
            // Straight-line fallthrough into the next block.
            uint64_t fall = 0;
            if (CheckedAddressAdd(b.insns.back().address, b.insns.back().length, fall)) {
                auto f = blockOf.find(fall);
                if (f != blockOf.end()) b.succ.push_back(f->second);
            }
            continue;
        }
        b.isReturn = isRet(transfer);
        b.isNoReturnCall = isAnalystNoreturnCall(transfer);
        b.isUncond = isUncondJmp(transfer);
        if (b.isReturn || b.isNoReturnCall ||
            InstructionIsSubroutineReturn(transfer)) continue;
        // Resolved jump table: link every case target as a successor (no fallthrough).
        if (auto t = tables.find(transfer.address); t != tables.end() && !t->second.empty()) {
            b.isSwitch = true;
            b.caseTargets = t->second;
            for (size_t caseIndex = 0; caseIndex < t->second.size(); ++caseIndex) {
                const uint64_t tgt = t->second[caseIndex];
                b.switchCases.push_back({ static_cast<int64_t>(caseIndex), tgt, true });
                auto bo = blockOf.find(tgt);
                if (bo != blockOf.end() &&
                    std::find(b.succ.begin(), b.succ.end(), bo->second) == b.succ.end())
                    b.succ.push_back(bo->second);
            }
            continue;
        }
        // In-encoding switch (JVM tableswitch/lookupswitch): every case plus the
        // default (branchTarget) is a successor; switches never fall through.
        if (!transfer.switchInfo.cases.empty() || transfer.switchInfo.defaultTargetValid ||
            !transfer.extraTargets.empty()) {
            b.isSwitch = true;
            auto link = [&](uint64_t tgt) {
                auto bo = blockOf.find(tgt);
                if (bo != blockOf.end() &&
                    std::find(b.succ.begin(), b.succ.end(), bo->second) == b.succ.end())
                    b.succ.push_back(bo->second);
            };
            if (!transfer.switchInfo.cases.empty() || transfer.switchInfo.defaultTargetValid) {
                b.switchDefaultTarget = transfer.switchInfo.defaultTarget;
                b.switchDefaultTargetValid = transfer.switchInfo.defaultTargetValid;
                for (const auto& c : transfer.switchInfo.cases) {
                    b.switchCases.push_back({ c.value, c.target, c.targetValid });
                    if (c.targetValid) { b.caseTargets.push_back(c.target); link(c.target); }
                }
                if (b.switchDefaultTargetValid) link(b.switchDefaultTarget);
            } else {
                for (size_t caseIndex = 0; caseIndex < transfer.extraTargets.size(); ++caseIndex) {
                    const uint64_t tgt = transfer.extraTargets[caseIndex];
                    b.caseTargets.push_back(tgt);
                    b.switchCases.push_back({ static_cast<int64_t>(caseIndex), tgt, true });
                    link(tgt);
                }
                uint64_t directTarget = 0;
                if (directTargetOf(transfer, directTarget)) {
                    b.switchDefaultTarget = directTarget;
                    b.switchDefaultTargetValid = true;
                    link(directTarget);
                }
            }
            continue;
        }
        uint64_t directTarget = 0;
        if (directTargetOf(transfer, directTarget)) {
            auto t = blockOf.find(directTarget);
            if (t != blockOf.end()) b.succ.push_back(t->second);
        }
        if (!b.isUncond) { // conditional branch also falls through
            auto f = blockOf.find(b.end);
            if (f != blockOf.end()) b.succ.push_back(f->second);
        }
    }
    pruneUnreachableBlocks(g, {va});
    return g;
}

ControlFlowGraph BuildCFG(const std::vector<CFGCodeChunk>& chunks,
                          IDisassembler& dis, size_t maxInsns,
                          const JumpTableResolver& resolveTable,
                          const NoreturnCallResolver& resolveNoreturnCall,
                          const DirectTargetResolver& resolveDirectTarget) {
    ControlFlowGraph g;
    if (chunks.empty()) {
        g.complete = false;
        g.incompleteReason = "no function chunks were supplied";
        return g;
    }
    g.funcStart = chunks.front().va;
    auto incomplete = [&](const char* reason) {
        if (g.complete) g.incompleteReason = reason;
        g.complete = false;
    };

    struct Node { Instruction in; size_t chunk = 0; };
    std::vector<Node> nodes;
    std::vector<uint64_t> chunkFirst(chunks.size(), 0);
    std::vector<char> chunkHasInstruction(chunks.size(), 0);
    bool budgetExhausted = false;
    struct ChunkRange { uint64_t begin = 0, end = 0; };
    std::vector<ChunkRange> ranges(chunks.size());
    for (size_t ci = 0; ci < chunks.size(); ++ci) {
        const CFGCodeChunk& chunk = chunks[ci];
        if (!chunk.data || !chunk.size) { incomplete("an empty or unmapped function chunk was supplied"); continue; }
        const size_t addressable = ClampAddressableBytes(chunk.va, chunk.size);
        if (!addressable) { incomplete("a function chunk has no representable address range"); continue; }
        if (addressable != chunk.size) incomplete("a function chunk address range was clamped");
        ranges[ci] = { chunk.va, SaturatingAddressAdd(chunk.va, addressable) };
        for (size_t prior = 0; prior < ci; ++prior) {
            if (ranges[prior].begin == ranges[prior].end) continue;
            if (ranges[ci].begin < ranges[prior].end && ranges[prior].begin < ranges[ci].end)
                incomplete("function chunks have overlapping address ranges");
        }
        if (nodes.size() >= maxInsns) { budgetExhausted = true; break; }

        size_t off = 0;
        while (off < addressable && nodes.size() < maxInsns) {
            uint64_t atVA = 0;
            if (!CheckedAddressAdd(chunk.va, static_cast<uint64_t>(off), atVA)) {
                incomplete("instruction address overflow in a function chunk"); break;
            }
            Instruction in;
            if (!dis.decodeOne(chunk.data + off, addressable - off, atVA, in)) {
                incomplete("decoder stopped before the end of a function chunk"); break;
            }
            if (!in.length || in.length > addressable - off) {
                incomplete("decoder returned an invalid instruction length in a function chunk"); break;
            }
            in.address = atVA;
            if (!chunkHasInstruction[ci]) { chunkFirst[ci] = atVA; chunkHasInstruction[ci] = 1; }
            nodes.push_back({ std::move(in), ci });
            off += nodes.back().in.length;
        }
        g.decodedBytes += off;
        if (off < addressable && nodes.size() >= maxInsns) { budgetExhausted = true; break; }
    }
    if (budgetExhausted) incomplete("instruction budget exhausted while decoding function chunks");
    g.decodedInstructions = nodes.size();
    if (nodes.empty()) return g;

    std::stable_sort(nodes.begin(), nodes.end(), [](const Node& a, const Node& b) {
        return a.in.address < b.in.address;
    });
    // Overlapping chunks are ambiguous: keep the first supplied decoding at a VA
    // deterministically, but make the graph explicitly incomplete.
    std::vector<Node> unique;
    unique.reserve(nodes.size());
    for (Node& node : nodes) {
        if (!unique.empty() && unique.back().in.address == node.in.address) {
            incomplete("function chunks overlap at an instruction address");
            continue;
        }
        unique.push_back(std::move(node));
    }
    nodes.swap(unique);
    g.decodedInstructions = nodes.size();

    std::unordered_map<uint64_t, size_t> idx;
    for (size_t i = 0; i < nodes.size(); ++i) idx[nodes[i].in.address] = i;
    auto contiguousNext = [&](size_t i, uint64_t& nextAddress) {
        if (i + 1 >= nodes.size() || nodes[i + 1].chunk != nodes[i].chunk) return false;
        if (!CheckedAddressAdd(nodes[i].in.address, nodes[i].in.length, nextAddress)) return false;
        return nodes[i + 1].in.address == nextAddress;
    };
    auto directTargetOf = [&](const Instruction& instruction, uint64_t& target) {
        return resolveDirectTarget ? resolveDirectTarget(instruction, target)
                                   : TryGetDirectTarget(instruction, target);
    };
    auto isAnalystNoreturnCall = [&](const Instruction& instruction) {
        if (!resolveNoreturnCall || !InstructionIsCall(instruction)) return false;
        uint64_t target = 0;
        return (directTargetOf(instruction, target) ||
                staticCallMemoryTarget(instruction, target)) &&
               resolveNoreturnCall(target);
    };
    auto blockEnding = [&](const Instruction& instruction) {
        return endsBlock(instruction) || isAnalystNoreturnCall(instruction);
    };
    auto afterDelaySlots = [&](size_t transferIndex, uint64_t& address) {
        size_t finalIndex = transferIndex;
        uint8_t remaining = nodes[transferIndex].in.flow.delaySlots;
        while (remaining) {
            uint64_t expected = 0;
            if (!contiguousNext(finalIndex, expected)) {
                incomplete("a control-transfer delay slot is missing from its function chunk");
                return false;
            }
            ++finalIndex; --remaining;
        }
        return CheckedAddressAdd(nodes[finalIndex].in.address, nodes[finalIndex].in.length, address);
    };

    std::unordered_map<uint64_t, std::vector<uint64_t>> tables;
    if (resolveTable) {
        for (const Node& node : nodes) {
            const Instruction& in = node.in;
            uint64_t directTarget = 0;
            if (!blockEnding(in) || !isUncondJmp(in) ||
                directTargetOf(in, directTarget)) continue;
            ResolvedJumpTable resolved = resolveTable(in);
            if (resolved.truncated) {
                std::string reason = "jump-table recovery reached its entry cap";
                if (!resolved.evidence.empty()) reason += " (" + resolved.evidence + ")";
                incomplete(reason.c_str());
            }
            std::vector<uint64_t> kept;
            for (uint64_t target : resolved.targets) {
                if (idx.count(target)) kept.push_back(target);
                else incomplete("a resolved switch target is outside the supplied function chunks");
            }
            if (!kept.empty()) tables[in.address] = std::move(kept);
        }
    }

    std::set<uint64_t> leaders;
    for (size_t ci = 0; ci < chunks.size(); ++ci)
        if (chunkHasInstruction[ci] && idx.count(chunkFirst[ci])) leaders.insert(chunkFirst[ci]);
    leaders.insert(g.funcStart);
    for (size_t i = 0; i < nodes.size(); ++i) {
        const Instruction& in = nodes[i].in;
        if (!blockEnding(in)) continue;
        uint64_t fall = 0;
        if (!isAnalystNoreturnCall(in) && afterDelaySlots(i, fall)) {
            auto next = idx.find(fall);
            if (next != idx.end() && nodes[next->second].chunk == nodes[i].chunk) leaders.insert(fall);
        }
        uint64_t target = 0;
        if (directTargetOf(in, target)) {
            if (idx.count(target)) leaders.insert(target);
            else if (InstructionEndsBlock(in) && !InstructionIsReturn(in) &&
                     !InstructionIsSubroutineReturn(in))
                incomplete("an explicit branch target is outside the supplied function chunks");
        }
        if (!in.switchInfo.cases.empty() || in.switchInfo.defaultTargetValid) {
            for (const auto& c : in.switchInfo.cases) {
                if (!c.targetValid || !idx.count(c.target)) incomplete("a switch case target is missing from the supplied function chunks");
                else leaders.insert(c.target);
            }
            if (in.switchInfo.defaultTargetValid) {
                if (idx.count(in.switchInfo.defaultTarget)) leaders.insert(in.switchInfo.defaultTarget);
                else incomplete("a switch default target is outside the supplied function chunks");
            }
        } else {
            for (uint64_t t : in.extraTargets) {
                if (idx.count(t)) leaders.insert(t);
                else incomplete("an encoded switch target is outside the supplied function chunks");
            }
        }
    }
    for (const auto& table : tables) for (uint64_t target : table.second) leaders.insert(target);

    for (uint64_t leader : leaders) {
        auto found = idx.find(leader);
        if (found == idx.end()) continue;
        BasicBlock block;
        block.start = leader;
        size_t k = found->second;
        while (k < nodes.size()) {
            if (k != found->second && leaders.count(nodes[k].in.address)) break;
            if (k != found->second) {
                uint64_t expected = 0;
                if (nodes[k].chunk != nodes[k - 1].chunk ||
                    !CheckedAddressAdd(nodes[k - 1].in.address, nodes[k - 1].in.length, expected) ||
                    nodes[k].in.address != expected) break;
            }
            block.insns.push_back(nodes[k].in);
            if (blockEnding(nodes[k].in)) {
                block.transferIndex = block.insns.size() - 1;
                uint8_t remaining = nodes[k].in.flow.delaySlots;
                while (remaining) {
                    uint64_t expected = 0;
                    if (!contiguousNext(k, expected)) break;
                    ++k; block.insns.push_back(nodes[k].in); --remaining;
                }
                break;
            }
            ++k;
        }
        if (block.insns.empty()) continue;
        block.end = SaturatingAddressAdd(block.insns.back().address, block.insns.back().length);
        g.blocks.push_back(std::move(block));
    }

    // Every consumer historically treats block zero as the CFG entry. Chunk
    // addresses can be out of order (a cold extent may have a lower VA), so put
    // the caller-authoritative first chunk entry first before assigning edges.
    auto entryBlock = std::find_if(g.blocks.begin(), g.blocks.end(), [&](const BasicBlock& block) {
        return block.start == g.funcStart;
    });
    if (entryBlock == g.blocks.end()) incomplete("the function entry is not decoded in the supplied chunks");
    else if (entryBlock != g.blocks.begin()) std::rotate(g.blocks.begin(), entryBlock, entryBlock + 1);

    std::unordered_map<uint64_t, size_t> blockOf;
    std::unordered_map<uint64_t, size_t> chunkOf;
    for (const Node& node : nodes) chunkOf[node.in.address] = node.chunk;
    for (size_t i = 0; i < g.blocks.size(); ++i) blockOf[g.blocks[i].start] = i;
    for (BasicBlock& block : g.blocks) {
        if (block.insns.empty()) continue;
        const Instruction& transfer = BlockTransferInstruction(block);
        const size_t ownerChunk = chunkOf[block.start];
        auto link = [&](uint64_t target) {
            auto it = blockOf.find(target);
            if (it != blockOf.end() && std::find(block.succ.begin(), block.succ.end(), it->second) == block.succ.end())
                block.succ.push_back(it->second);
        };
        auto fallthrough = [&]() {
            auto it = blockOf.find(block.end);
            if (it != blockOf.end() && chunkOf[block.end] == ownerChunk) block.succ.push_back(it->second);
        };
        if (block.transferIndex >= block.insns.size()) { fallthrough(); continue; }
        block.isReturn = isRet(transfer);
        block.isNoReturnCall = isAnalystNoreturnCall(transfer);
        block.isUncond = isUncondJmp(transfer);
        if (block.isReturn || block.isNoReturnCall ||
            InstructionIsSubroutineReturn(transfer)) continue;
        if (auto table = tables.find(transfer.address); table != tables.end() && !table->second.empty()) {
            block.isSwitch = true; block.caseTargets = table->second;
            for (size_t c = 0; c < table->second.size(); ++c) {
                block.switchCases.push_back({ static_cast<int64_t>(c), table->second[c], true });
                link(table->second[c]);
            }
            continue;
        }
        if (!transfer.switchInfo.cases.empty() || transfer.switchInfo.defaultTargetValid || !transfer.extraTargets.empty()) {
            block.isSwitch = true;
            if (!transfer.switchInfo.cases.empty() || transfer.switchInfo.defaultTargetValid) {
                block.switchDefaultTarget = transfer.switchInfo.defaultTarget;
                block.switchDefaultTargetValid = transfer.switchInfo.defaultTargetValid;
                for (const auto& c : transfer.switchInfo.cases) {
                    block.switchCases.push_back({ c.value, c.target, c.targetValid });
                    if (c.targetValid) { block.caseTargets.push_back(c.target); link(c.target); }
                }
                if (block.switchDefaultTargetValid) link(block.switchDefaultTarget);
            } else {
                for (size_t c = 0; c < transfer.extraTargets.size(); ++c) {
                    const uint64_t target = transfer.extraTargets[c];
                    block.caseTargets.push_back(target);
                    block.switchCases.push_back({ static_cast<int64_t>(c), target, true });
                    link(target);
                }
                uint64_t target = 0;
                if (directTargetOf(transfer, target)) {
                    block.switchDefaultTarget = target; block.switchDefaultTargetValid = true; link(target);
                }
            }
            continue;
        }
        uint64_t target = 0;
        if (directTargetOf(transfer, target)) link(target);
        if (!block.isUncond) fallthrough();
    }
    std::vector<uint64_t> roots;
    roots.reserve(chunks.size());
    for (size_t ci = 0; ci < chunks.size(); ++ci)
        if (chunkHasInstruction[ci]) roots.push_back(chunkFirst[ci]);
    pruneUnreachableBlocks(g, roots);
    return g;
}

} // namespace ds
