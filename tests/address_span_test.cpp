// Dependency-light UINT64_MAX address-span and CFG containment regression test.
#include "Core/AddressSpan.h"
#include "Core/CFG.h"

#include <cstdint>
#include <cstdio>
#include <limits>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

struct ByteDis final : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "byte-test"; }

    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& out) override {
        if (!data || !size) return false;
        out = Instruction{};
        out.address = 0; // CFG must normalize a misbehaving custom backend.
        out.length = 1;
        out.mnemonic = "nop";
        if (*data == 1) {
            out.mnemonic = "jne";
            out.isBranch = true;
            out.branchTarget = (std::numeric_limits<uint64_t>::max)();
            out.branchTargetValid = true;
        } else if (*data == 2) {
            out.mnemonic = "ret";
            out.isBranch = out.isRet = true;
        } else if (*data == 3) {
            out.mnemonic = "bne";
            out.isBranch = true;
            out.branchTarget = va + 4;
            out.branchTargetValid = true;
            out.flow.kind = FlowKind::ConditionalBranch;
            out.flow.directTarget = va + 4;
            out.flow.directTargetValid = true;
            out.flow.delaySlots = 1;
        } else if (*data == 4) {
            out.mnemonic = "addiu";
        }
        (void)va;
        return true;
    }

    std::vector<Instruction> disassemble(const uint8_t*, size_t, uint64_t,
                                         size_t) override { return {}; }
};

int main() {
    constexpr uint64_t kMax = (std::numeric_limits<uint64_t>::max)();
    uint64_t out = 0;

    CHECK(CheckedAddressAdd(kMax - 1, 1, out) && out == kMax);
    CHECK(!CheckedAddressAdd(kMax - 1, 2, out));
    CHECK(CheckedAddressAddSigned(5, -5, out) && out == 0);
    CHECK(!CheckedAddressAddSigned(0, -1, out));
    CHECK(CheckedAddressAddSigned(uint64_t{1} << 63,
                                  (std::numeric_limits<int64_t>::min)(), out) && out == 0);
    CHECK(!CheckedAddressAddSigned(kMax, 1, out));

    CHECK(ClampAddressableBytes(0, 17) == 17);
    CHECK(ClampAddressableBytes(kMax - 1, 17) == 2);
    CHECK(ClampAddressableBytes(kMax, 17) == 1);
    CHECK(AddressInSpan(kMax - 1, 2, kMax - 1));
    CHECK(AddressInSpan(kMax - 1, 2, kMax));
    CHECK(!AddressInSpan(kMax - 1, 2, 0));
    CHECK(SaturatingAddressAdd(kMax, 1) == kMax);

    // The supplied buffer is four bytes, but only two byte addresses exist from
    // UINT64_MAX-1. CFG must decode those two and never manufacture VA 0.
    const uint8_t code[] = {1, 2, 0, 0};
    ByteDis dis;
    ControlFlowGraph g = BuildCFG(code, sizeof(code), kMax - 1, dis, 16);
    CHECK(g.blocks.size() == 2);
    size_t instructionCount = 0;
    bool sawPenultimate = false, sawMax = false, sawZero = false;
    for (const BasicBlock& block : g.blocks) {
        CHECK(block.start >= kMax - 1);
        CHECK(block.end == kMax); // true exclusive 2^64 is represented by saturation
        for (const Instruction& in : block.insns) {
            ++instructionCount;
            sawPenultimate |= in.address == kMax - 1;
            sawMax |= in.address == kMax;
            sawZero |= in.address == 0;
        }
    }
    CHECK(instructionCount == 2 && sawPenultimate && sawMax && !sawZero);

    // A delayed branch owns its architectural delay slot. Its fallthrough edge
    // starts after that slot, while the direct edge still uses the decoder's
    // structured target. The transfer need not be the block's final instruction.
    const uint8_t delayed[] = {3, 4, 2, 0, 2};
    ControlFlowGraph delayedGraph = BuildCFG(delayed, sizeof(delayed), 0x100, dis, 16);
    const BasicBlock* entry = nullptr;
    for (const BasicBlock& block : delayedGraph.blocks)
        if (block.start == 0x100) entry = &block;
    CHECK(entry != nullptr);
    if (entry) {
        CHECK(entry->insns.size() == 2);
        CHECK(entry->transferIndex == 0);
        CHECK(entry->insns[1].address == 0x101);
        CHECK(entry->end == 0x102);
        CHECK(BlockTransferInstruction(*entry).address == 0x100);
        bool sawFallthrough = false, sawTarget = false;
        for (size_t successor : entry->succ) {
            CHECK(successor < delayedGraph.blocks.size());
            if (successor >= delayedGraph.blocks.size()) continue;
            sawFallthrough |= delayedGraph.blocks[successor].start == 0x102;
            sawTarget |= delayedGraph.blocks[successor].start == 0x104;
        }
        CHECK(sawFallthrough && sawTarget);
    }

    if (!g_fail) std::printf("address_span_test: all checks passed\n");
    return g_fail ? 1 : 0;
}
