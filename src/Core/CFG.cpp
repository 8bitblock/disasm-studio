#include "CFG.h"

#include <algorithm>
#include <set>
#include <string>
#include <unordered_map>

namespace ds {

// A block-ending control transfer: jmp/jcc/ret (but NOT call, which returns).
static bool endsBlock(const Instruction& in) { return in.isBranch && !in.isCall; }
static bool isRet(const Instruction& in) {
    // Honor the decoder's own return flag (set for non-x86 returns — blr / jr $ra /
    // bx lr / ... — as well as x86) so those blocks are tagged isReturn and don't get a
    // spurious fallthrough successor; keep the x86 mnemonic checks as a fallback.
    return in.isRet || in.mnemonic == "ret" || in.mnemonic == "retn" || in.mnemonic == "retf";
}
static bool isUncondJmp(const Instruction& in) {
    return in.mnemonic == "jmp" || in.mnemonic == "jmpq" ||
           in.mnemonic == "goto" || in.mnemonic == "goto_w";   // JVM unconditionals
}

ControlFlowGraph BuildCFG(const uint8_t* code, size_t size, uint64_t va,
                          IDisassembler& dis, size_t maxInsns,
                          const JumpTableResolver& resolveTable) {
    ControlFlowGraph g;
    g.funcStart = va;
    if (!code || !size) return g;

    // 1. Linear decode of the window.
    std::vector<Instruction> lin;
    size_t off = 0;
    while (off < size && lin.size() < maxInsns) {
        Instruction in;
        if (!dis.decodeOne(code + off, size - off, va + off, in)) break;
        if (!in.length) break;
        lin.push_back(in);
        off += in.length;
        // Heuristic stop: once we pass a ret that has no in-range successors we
        // still continue (functions have multiple rets); the maxInsns/size caps.
    }
    if (lin.empty()) return g;

    const uint64_t lo = va;
    const uint64_t hi = va + off;

    std::unordered_map<uint64_t, size_t> idx;
    for (size_t i = 0; i < lin.size(); ++i) idx[lin[i].address] = i;

    // 1b. Resolve indirect jumps (jmp [table + idx*N]) to jump-table case targets.
    // Keyed by the jmp instruction address; only targets that land on a decoded
    // instruction boundary are kept (so each can become its own basic block).
    std::unordered_map<uint64_t, std::vector<uint64_t>> tables;
    if (resolveTable) {
        for (const auto& in : lin) {
            if (!endsBlock(in) || !isUncondJmp(in)) continue;
            if (in.branchTarget) continue;                              // direct jmp: handled normally
            if (in.operands.find('[') == std::string::npos) continue;  // need a memory (table) operand
            std::vector<uint64_t> kept;
            for (uint64_t t : resolveTable(in)) if (idx.count(t)) kept.push_back(t);
            if (!kept.empty()) tables[in.address] = std::move(kept);
        }
    }

    // 2. Leaders: function start, branch targets, fallthroughs, and switch cases.
    std::set<uint64_t> leaders;
    leaders.insert(va);
    for (const auto& in : lin) {
        if (!endsBlock(in)) continue;
        uint64_t fall = in.address + in.length;
        if (fall >= lo && fall < hi) leaders.insert(fall);
        if (in.branchTarget && in.branchTarget >= lo && in.branchTarget < hi)
            leaders.insert(in.branchTarget);
        for (uint64_t t : in.extraTargets)                      // in-encoding switch cases (JVM)
            if (t >= lo && t < hi) leaders.insert(t);
    }
    for (const auto& t : tables) for (uint64_t tgt : t.second) leaders.insert(tgt);

    // 3. Build blocks spanning [leader, nextLeader) until a block-ender.
    std::vector<uint64_t> ls(leaders.begin(), leaders.end()); // sorted ascending
    for (size_t li = 0; li < ls.size(); ++li) {
        BasicBlock b;
        b.start = ls[li];
        uint64_t blockLimit = (li + 1 < ls.size()) ? ls[li + 1] : hi;
        auto it = idx.find(b.start);
        if (it == idx.end()) continue;
        size_t k = it->second;
        while (k < lin.size() && lin[k].address < blockLimit) {
            b.insns.push_back(lin[k]);
            if (endsBlock(lin[k])) { ++k; break; }
            ++k;
        }
        if (b.insns.empty()) continue;
        b.end = b.insns.back().address + b.insns.back().length;
        g.blocks.push_back(std::move(b));
    }

    std::unordered_map<uint64_t, size_t> blockOf;
    for (size_t i = 0; i < g.blocks.size(); ++i) blockOf[g.blocks[i].start] = i;

    // 4. Edges from each block's terminator.
    for (auto& b : g.blocks) {
        if (b.insns.empty()) continue;
        const Instruction& last = b.insns.back();
        if (!endsBlock(last)) {
            // Straight-line fallthrough into the next block.
            auto f = blockOf.find(b.end);
            if (f != blockOf.end()) b.succ.push_back(f->second);
            continue;
        }
        b.isReturn = isRet(last);
        b.isUncond = isUncondJmp(last);
        if (b.isReturn) continue;
        // Resolved jump table: link every case target as a successor (no fallthrough).
        if (auto t = tables.find(last.address); t != tables.end() && !t->second.empty()) {
            b.isSwitch = true;
            b.caseTargets = t->second;
            for (uint64_t tgt : t->second) {
                auto bo = blockOf.find(tgt);
                if (bo != blockOf.end() &&
                    std::find(b.succ.begin(), b.succ.end(), bo->second) == b.succ.end())
                    b.succ.push_back(bo->second);
            }
            continue;
        }
        // In-encoding switch (JVM tableswitch/lookupswitch): every case plus the
        // default (branchTarget) is a successor; switches never fall through.
        if (!last.extraTargets.empty()) {
            b.isSwitch = true;
            b.caseTargets = last.extraTargets;
            auto link = [&](uint64_t tgt) {
                auto bo = blockOf.find(tgt);
                if (bo != blockOf.end() &&
                    std::find(b.succ.begin(), b.succ.end(), bo->second) == b.succ.end())
                    b.succ.push_back(bo->second);
            };
            for (uint64_t tgt : last.extraTargets) link(tgt);
            if (last.branchTarget) link(last.branchTarget);
            continue;
        }
        if (last.branchTarget) {
            auto t = blockOf.find(last.branchTarget);
            if (t != blockOf.end()) b.succ.push_back(t->second);
        }
        if (!b.isUncond) { // conditional branch also falls through
            auto f = blockOf.find(last.address + last.length);
            if (f != blockOf.end()) b.succ.push_back(f->second);
        }
    }
    return g;
}

} // namespace ds
