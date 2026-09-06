//
// jvmdisasm_test.cpp
// Off-target tests for src/Disasm/JvmDisassembler.cpp: full decode of the
// synthetic Main.main bytecode (lengths, mnemonics, branch targets), constant-
// pool symbolication via the attached class (comments, LOCAL invokestatic ->
// branchTarget), tableswitch alignment padding off the true bci, wide forms,
// lookupswitch, db-fallback resync, and CFG integration (goto = unconditional,
// switch cases = successors, no switch fallthrough).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\jvmdisasm_test.cpp src\Core\JvmClass.cpp ^
//      src\Disasm\JvmDisassembler.cpp src\Core\CFG.cpp
//   .\jvmdisasm_test.exe
//
#include "Core/CFG.h"
#include "Core/JvmClass.h"
#include "Disasm/JvmDisassembler.h"
#include "jvm_testclass.h"

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <limits>
#include <memory>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    ClassBytes tc = jvmtest::buildTestClass();
    auto cf = std::make_shared<JvmClassFile>(ParseJavaClass(tc.bytes.data(), tc.bytes.size()));
    CHECK(cf->ok);

    const uint64_t mainVA   = tc.mainCodeOff;     // identity mapping: VA == file offset
    const uint64_t helperVA = tc.helperCodeOff;
    const uint8_t* code     = tc.bytes.data() + tc.mainCodeOff;

    JvmDisassembler dis;
    dis.attachClass(cf);

    // ---- full decode of main (symbolicated) ----------------------------------
    auto insns = dis.disassemble(code, 41, mainVA, 0);
    CHECK(insns.size() == 11);
    if (insns.size() == 11) {
        const uint32_t lens[11] = {2, 3, 2, 3, 3, 1, 1, 1, 1, 23, 1};
        const char* mns[11] = {"ldc", "invokestatic", "bipush", "iinc", "goto",
                               "nop", "nop", "nop", "iconst_0", "tableswitch", "return"};
        for (int i = 0; i < 11; ++i) {
            CHECK(insns[i].length == lens[i]);
            CHECK(insns[i].mnemonic == mns[i]);
        }
        CHECK(insns[0].operands == "#2");
        CHECK(insns[0].comment == "\"Hello\"");           // ldc of a String constant
        CHECK(insns[0].typedOperands.size() == 1);
        if (insns[0].typedOperands.size() == 1) {
            CHECK(insns[0].typedOperands[0].kind == OperandKind::Immediate);
            CHECK(insns[0].typedOperands[0].immediate == 2);
            CHECK(insns[0].typedOperands[0].widthBits == 8);
            CHECK(!insns[0].typedOperands[0].pcRelative);
        }

        CHECK(insns[1].isCall && insns[1].isBranch);
        CHECK(insns[1].branchTarget == helperVA);          // LOCAL method resolved
        CHECK(insns[1].comment == "Main.helper:()I");
        CHECK(insns[1].flow.kind == FlowKind::DirectCall);
        CHECK(insns[1].flow.directTargetValid);
        CHECK(insns[1].flow.directTarget == helperVA);
        CHECK(insns[1].typedOperands.size() == 1);
        if (insns[1].typedOperands.size() == 1) {
            CHECK(insns[1].typedOperands[0].kind == OperandKind::Immediate);
            CHECK(insns[1].typedOperands[0].immediate == 12); // CONSTANT_Methodref index
            CHECK(insns[1].typedOperands[0].widthBits == 16);
        }

        CHECK(insns[2].operands == "7");                   // bipush
        CHECK(insns[3].operands == "1, 1");                // iinc
        CHECK(insns[2].typedOperands.size() == 1);
        if (insns[2].typedOperands.size() == 1) {
            CHECK(insns[2].typedOperands[0].kind == OperandKind::Immediate);
            CHECK(insns[2].typedOperands[0].immediate == 7);
            CHECK(insns[2].typedOperands[0].immediateSigned);
        }
        CHECK(insns[3].typedOperands.size() == 2);
        if (insns[3].typedOperands.size() == 2) {
            CHECK(insns[3].typedOperands[0].immediate == 1); // local slot
            CHECK(insns[3].typedOperands[1].immediate == 1); // signed increment
            CHECK(insns[3].typedOperands[1].immediateSigned);
        }

        CHECK(insns[4].isBranch && !insns[4].isCall && !insns[4].isRet);
        CHECK(insns[4].branchTarget == mainVA + 16);       // goto
        CHECK(insns[4].flow.kind == FlowKind::UnconditionalBranch);
        CHECK(insns[4].flow.directTargetValid && insns[4].flow.directTarget == mainVA + 16);
        CHECK(insns[4].typedOperands.size() == 1 &&
              insns[4].typedOperands[0].kind == OperandKind::Immediate &&
              insns[4].typedOperands[0].pcRelative);

        const Instruction& sw = insns[9];                  // tableswitch @ bci 17, pad 2
        CHECK(sw.address == mainVA + 17);
        CHECK(sw.isBranch && !sw.isCall);
        CHECK(sw.branchTarget == mainVA + 13);             // default
        CHECK(sw.flow.kind == FlowKind::Switch);
        CHECK(sw.flow.directTargetValid && sw.flow.directTarget == mainVA + 13);
        CHECK(sw.typedOperands.size() == 1 &&
              sw.typedOperands[0].kind == OperandKind::Immediate &&
              sw.typedOperands[0].pcRelative);
        if (sw.typedOperands.size() == 1)
            CHECK(sw.typedOperands[0].immediate ==
                  static_cast<uint64_t>(static_cast<int64_t>(-4)));
        CHECK(sw.extraTargets.size() == 2);
        CHECK(sw.switchInfo.defaultTargetValid &&
              sw.switchInfo.defaultTarget == mainVA + 13);
        CHECK(sw.switchInfo.cases.size() == 2);
        if (sw.switchInfo.cases.size() == 2) {
            CHECK(sw.switchInfo.cases[0].value == 0 &&
                  sw.switchInfo.cases[0].targetValid &&
                  sw.switchInfo.cases[0].target == mainVA + 16);
            CHECK(sw.switchInfo.cases[1].value == 1 &&
                  sw.switchInfo.cases[1].targetValid &&
                  sw.switchInfo.cases[1].target == mainVA + 13);
        }
        if (sw.extraTargets.size() == 2) {
            CHECK(sw.extraTargets[0] == mainVA + 16);      // case 0
            CHECK(sw.extraTargets[1] == mainVA + 13);      // case 1
        }
        CHECK(sw.operands.find("0..1") != std::string::npos);

        CHECK(insns[10].isRet);                            // return
        CHECK(insns[10].flow.kind == FlowKind::Return);
        CHECK(!insns[10].flow.directTargetValid);
    }

    // decodeOne mid-method: the class context supplies the true bci for padding.
    {
        Instruction one;
        CHECK(dis.decodeOne(code + 17, 41 - 17, mainVA + 17, one));
        CHECK(one.mnemonic == "tableswitch" && one.length == 23);
        CHECK(one.branchTarget == mainVA + 13);
    }

    // helper decodes too (bipush 42; ireturn) and ireturn flags as a return.
    {
        auto h = dis.disassemble(tc.bytes.data() + tc.helperCodeOff, 3, helperVA, 0);
        CHECK(h.size() == 2);
        if (h.size() == 2) {
            CHECK(h[0].mnemonic == "bipush" && h[0].operands == "42");
            CHECK(h[1].mnemonic == "ireturn" && h[1].isRet);
        }
    }

    // ---- without class context: raw "#n", padding from the window start ------
    {
        JvmDisassembler bare;
        auto b = bare.disassemble(code, 41, mainVA, 0);
        CHECK(b.size() == 11);
        if (b.size() == 11) {
            CHECK(b[0].operands == "#2" && b[0].comment.empty());
            CHECK(b[1].branchTarget == 0);                 // no local resolution
            CHECK(b[1].flow.kind == FlowKind::DirectCall);
            CHECK(!b[1].flow.directTargetValid);
            CHECK(b[9].mnemonic == "tableswitch" && b[9].length == 23);
            CHECK(b[9].extraTargets.size() == 2);          // bci tracked from window start
        }
    }

    // ---- wide forms ------------------------------------------------------------
    {
        JvmDisassembler bare;
        const uint8_t wiinc[] = {0xC4, 0x84, 0x01, 0x00, 0x00, 0x02};
        Instruction in;
        CHECK(bare.decodeOne(wiinc, sizeof(wiinc), 0, in));
        CHECK(in.mnemonic == "iinc" && in.operands == "256, 2" && in.length == 6);

        const uint8_t wiload[] = {0xC4, 0x15, 0x01, 0x2C};
        CHECK(bare.decodeOne(wiload, sizeof(wiload), 0, in));
        CHECK(in.mnemonic == "iload" && in.operands == "300" && in.length == 4);

        const uint8_t wbad[] = {0xC4, 0x00};               // wide nop: invalid
        CHECK(!bare.decodeOne(wbad, sizeof(wbad), 0, in));
    }

    // JVM invocation dispatch and legacy jsr/ret subroutines are distinct
    // semantic concepts.  invokevirtual must not become a direct local call
    // merely because its constant-pool Methodref names this class.
    {
        Instruction in;
        const uint8_t invokevirtualLocal[] = {0xB6, 0x00, 0x0C};
        CHECK(dis.decodeOne(invokevirtualLocal, sizeof(invokevirtualLocal), mainVA, in));
        CHECK(in.isCall && in.flow.kind == FlowKind::IndirectCall);
        CHECK(!in.branchTargetValid && !in.flow.directTargetValid);

        JvmDisassembler bare;
        const uint8_t invokespecial[] = {0xB7, 0x00, 0x01};
        const uint8_t invokestatic[] = {0xB8, 0x00, 0x01};
        const uint8_t invokeinterface[] = {0xB9, 0x00, 0x01, 0x01, 0x00};
        const uint8_t invokedynamic[] = {0xBA, 0x00, 0x01, 0x00, 0x00};
        CHECK(bare.decodeOne(invokespecial, sizeof(invokespecial), 0, in));
        CHECK(in.flow.kind == FlowKind::DirectCall && !in.flow.directTargetValid);
        CHECK(bare.decodeOne(invokestatic, sizeof(invokestatic), 0, in));
        CHECK(in.flow.kind == FlowKind::DirectCall && !in.flow.directTargetValid);
        CHECK(bare.decodeOne(invokeinterface, sizeof(invokeinterface), 0, in));
        CHECK(in.flow.kind == FlowKind::IndirectCall);
        CHECK(bare.decodeOne(invokedynamic, sizeof(invokedynamic), 0, in));
        CHECK(in.flow.kind == FlowKind::IndirectCall);

        const uint8_t jsr[] = {0xA8, 0x00, 0x03};
        CHECK(bare.decodeOne(jsr, sizeof(jsr), 0x100, in));
        CHECK(in.isBranch && !in.isCall && !in.isRet);
        CHECK(in.flow.kind == FlowKind::SubroutineCall &&
              in.flow.directTargetValid && in.flow.directTarget == 0x103);
        CHECK(InstructionIsSubroutineCall(in) && !InstructionIsCall(in) &&
              InstructionEndsBlock(in));

        const uint8_t ret[] = {0xA9, 0x02};
        CHECK(bare.decodeOne(ret, sizeof(ret), 0x103, in));
        CHECK(in.isBranch && !in.isCall && !in.isRet);
        CHECK(in.flow.kind == FlowKind::SubroutineReturn);
        CHECK(InstructionIsSubroutineReturn(in) && !InstructionIsReturn(in) &&
              InstructionEndsBlock(in));

        const uint8_t wideRet[] = {0xC4, 0xA9, 0x01, 0x00};
        CHECK(bare.decodeOne(wideRet, sizeof(wideRet), 0x104, in));
        CHECK(in.flow.kind == FlowKind::SubroutineReturn && !in.isRet);

        const uint8_t athrow[] = {0xBF};
        CHECK(bare.decodeOne(athrow, sizeof(athrow), 0x108, in));
        CHECK(in.flow.kind == FlowKind::IndirectBranch && !InstructionIsReturn(in));
    }

    // jsr has both the subroutine target and ordinary continuation. JVM ret is
    // an indirect subroutine return and must never acquire a fabricated edge to
    // the physically following byte, in contiguous or noncontiguous CFG input.
    {
        JvmDisassembler bare;
        const uint8_t contiguous[] = {
            0xA8, 0x00, 0x04, // 0: jsr 4
            0xB1,             // 3: return (jsr continuation)
            0xA9, 0x00,       // 4: ret 0
            0xB1              // 6: unrelated physical successor
        };
        const ControlFlowGraph graph =
            BuildCFG(contiguous, sizeof(contiguous), 0, bare, 32);
        auto indexAt = [&](const ControlFlowGraph& candidate, uint64_t address) {
            for (size_t i = 0; i < candidate.blocks.size(); ++i)
                if (candidate.blocks[i].start == address) return i;
            return candidate.blocks.size();
        };
        const size_t jsrBlock = indexAt(graph, 0);
        const size_t continuation = indexAt(graph, 3);
        const size_t subroutine = indexAt(graph, 4);
        const size_t afterRet = indexAt(graph, 6);
        CHECK(jsrBlock < graph.blocks.size() && continuation < graph.blocks.size() &&
              subroutine < graph.blocks.size() && afterRet < graph.blocks.size());
        if (jsrBlock < graph.blocks.size()) {
            CHECK(std::find(graph.blocks[jsrBlock].succ.begin(),
                            graph.blocks[jsrBlock].succ.end(), continuation) !=
                  graph.blocks[jsrBlock].succ.end());
            CHECK(std::find(graph.blocks[jsrBlock].succ.begin(),
                            graph.blocks[jsrBlock].succ.end(), subroutine) !=
                  graph.blocks[jsrBlock].succ.end());
        }
        if (subroutine < graph.blocks.size()) {
            CHECK(InstructionIsSubroutineReturn(
                BlockTransferInstruction(graph.blocks[subroutine])));
            CHECK(!graph.blocks[subroutine].isReturn);
            CHECK(graph.blocks[subroutine].succ.empty());
        }

        const uint8_t mainChunk[] = {0xA8, 0x00, 0x10, 0xB1};
        const uint8_t subChunk[] = {0xA9, 0x00, 0xB1};
        const std::vector<CFGCodeChunk> chunks = {
            {mainChunk, sizeof(mainChunk), 0x100},
            {subChunk, sizeof(subChunk), 0x110}
        };
        const ControlFlowGraph chunked = BuildCFG(chunks, bare, 32);
        const size_t chunkJsr = indexAt(chunked, 0x100);
        const size_t chunkContinuation = indexAt(chunked, 0x103);
        const size_t chunkSubroutine = indexAt(chunked, 0x110);
        CHECK(chunkJsr < chunked.blocks.size() &&
              chunkContinuation < chunked.blocks.size() &&
              chunkSubroutine < chunked.blocks.size());
        if (chunkJsr < chunked.blocks.size()) {
            CHECK(std::find(chunked.blocks[chunkJsr].succ.begin(),
                            chunked.blocks[chunkJsr].succ.end(), chunkContinuation) !=
                  chunked.blocks[chunkJsr].succ.end());
            CHECK(std::find(chunked.blocks[chunkJsr].succ.begin(),
                            chunked.blocks[chunkJsr].succ.end(), chunkSubroutine) !=
                  chunked.blocks[chunkJsr].succ.end());
        }
        if (chunkSubroutine < chunked.blocks.size()) {
            CHECK(InstructionIsSubroutineReturn(
                BlockTransferInstruction(chunked.blocks[chunkSubroutine])));
            CHECK(!chunked.blocks[chunkSubroutine].isReturn);
            CHECK(chunked.blocks[chunkSubroutine].succ.empty());
        }
    }

    // A resolved target of zero is distinct from an unresolved branch. This is
    // the decoder-level contract used by raw mappings based at VA 0.
    {
        JvmDisassembler bare;
        const uint8_t goZero[] = { 0xA7, 0xFF, 0xFD }; // goto -3, decoded at VA 3
        Instruction in;
        CHECK(bare.decodeOne(goZero, sizeof(goZero), 3, in));
        CHECK(in.mnemonic == "goto" && in.branchTarget == 0 && HasBranchTarget(in));
        CHECK(in.flow.kind == FlowKind::UnconditionalBranch);
        CHECK(in.flow.directTargetValid && in.flow.directTarget == 0);

        const uint8_t loopToZero[] = { 0x00, 0x00, 0x00, 0xA7, 0xFF, 0xFD };
        ControlFlowGraph g = BuildCFG(loopToZero, sizeof(loopToZero), 0, bare, 32);
        size_t zeroBlock = g.blocks.size(), jumpBlock = g.blocks.size();
        for (size_t i = 0; i < g.blocks.size(); ++i) {
            if (g.blocks[i].start == 0) zeroBlock = i;
            for (const Instruction& decoded : g.blocks[i].insns)
                if (decoded.address == 3) jumpBlock = i;
        }
        bool linkedToZero = false;
        if (jumpBlock < g.blocks.size())
            for (size_t s : g.blocks[jumpBlock].succ) if (s == zeroBlock) linkedToZero = true;
        CHECK(zeroBlock < g.blocks.size() && jumpBlock < g.blocks.size() && linkedToZero);
    }

    // ---- lookupswitch at window start (pad 3) -----------------------------------
    {
        JvmDisassembler bare;
        const uint8_t lkp[] = {
            0xAB, 0x00, 0x00, 0x00,                        // opcode + 3 pad
            0x00, 0x00, 0x00, 0x10,                        // default +16
            0x00, 0x00, 0x00, 0x02,                        // npairs 2
            0x00, 0x00, 0x00, 0x05,  0x00, 0x00, 0x00, 0x14,   // 5 -> +20
            0x00, 0x00, 0x00, 0x09,  0x00, 0x00, 0x00, 0x18,   // 9 -> +24
        };
        auto v = bare.disassemble(lkp, sizeof(lkp), 0, 0);
        CHECK(v.size() == 1);
        if (v.size() == 1) {
            CHECK(v[0].mnemonic == "lookupswitch" && v[0].length == 28);
            CHECK(v[0].branchTarget == 0x10);
            CHECK(v[0].switchInfo.defaultTargetValid &&
                  v[0].switchInfo.defaultTarget == 0x10);
            CHECK(v[0].extraTargets.size() == 2);
            CHECK(v[0].switchInfo.cases.size() == 2);
            if (v[0].switchInfo.cases.size() == 2) {
                CHECK(v[0].switchInfo.cases[0].value == 5 &&
                      v[0].switchInfo.cases[0].target == 0x14);
                CHECK(v[0].switchInfo.cases[1].value == 9 &&
                      v[0].switchInfo.cases[1].target == 0x18);
            }
            if (v[0].extraTargets.size() == 2) {
                CHECK(v[0].extraTargets[0] == 0x14 && v[0].extraTargets[1] == 0x18);
            }
            CHECK(v[0].comment.find("5 -> 0x14") != std::string::npos);
            CHECK(v[0].typedOperands.size() == 1 &&
                  v[0].typedOperands[0].immediate == 0x10 &&
                  v[0].typedOperands[0].pcRelative);
        }

        uint8_t unsorted[sizeof(lkp)];
        std::copy(std::begin(lkp), std::end(lkp), std::begin(unsorted));
        // Change the second key from 9 to 4; lookupswitch keys must increase.
        unsorted[23] = 0x04;
        Instruction invalid;
        CHECK(!bare.decodeOne(unsorted, sizeof(unsorted), 0, invalid));
    }

    // ---- undecodable byte: db row, one-byte resync ------------------------------
    {
        JvmDisassembler bare;
        const uint8_t junk[] = {0xCB, 0x00};               // 0xCB unassigned
        Instruction in;
        CHECK(!bare.decodeOne(junk, sizeof(junk), 0, in));
        auto v = bare.disassemble(junk, sizeof(junk), 0, 0);
        CHECK(v.size() == 2);
        if (v.size() == 2) {
            CHECK(v[0].mnemonic == "db" && v[0].length == 1);
            CHECK(v[1].mnemonic == "nop");
        }
    }

    // ---- truncated buffers never read past the end ------------------------------
    {
        JvmDisassembler bare;
        Instruction in;
        const uint8_t tsw[] = {0xAA, 0x00, 0x00};          // tableswitch, no table
        CHECK(!bare.decodeOne(tsw, sizeof(tsw), 0, in));
        const uint8_t inv[] = {0xB8, 0x00};                // invokestatic, 1 operand byte
        CHECK(!bare.decodeOne(inv, sizeof(inv), 0, in));
    }

    // ---- top-of-address-space bulk decode and relative-target hardening ---------
    {
        constexpr uint64_t kMax = (std::numeric_limits<uint64_t>::max)();
        JvmDisassembler bare;
        const uint8_t nops[] = {0x00, 0x00, 0x00, 0x00};
        auto v = bare.disassemble(nops, sizeof(nops), kMax - 1, 0);
        CHECK(v.size() == 2);
        if (v.size() == 2) {
            CHECK(v[0].address == kMax - 1);
            CHECK(v[1].address == kMax);
        }

        // Three encoding bytes fit at kMax-2, but the +4 JVM target does not.
        // It must be rejected, never surfaced as wrapped low address 1.
        const uint8_t wrapGoto[] = {0xA7, 0x00, 0x04};
        Instruction in;
        CHECK(!bare.decodeOne(wrapGoto, sizeof(wrapGoto), kMax - 2, in));
        const uint8_t underflowGoto[] = {0xA7, 0xFF, 0xFC}; // -4 at VA 2
        CHECK(!bare.decodeOne(underflowGoto, sizeof(underflowGoto), 2, in));

        // tableswitch @ (kMax-19) has bci%4==0, hence three pad bytes and one
        // case. Its 20 encoding bytes fit exactly, but default +32 does not.
        const uint8_t wrapTable[] = {
            0xAA, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x20, // default +32
            0x00, 0x00, 0x00, 0x00, // low 0
            0x00, 0x00, 0x00, 0x00, // high 0
            0x00, 0x00, 0x00, 0x00, // case 0 -> self
        };
        CHECK(!bare.decodeOne(wrapTable, sizeof(wrapTable), kMax - 19, in));
    }

    // ---- CFG over main: goto unconditional, switch successors, no fallthrough ---
    {
        ControlFlowGraph g = BuildCFG(code, 41, mainVA, dis);
        auto blockAt = [&](uint64_t s) -> const BasicBlock* {
            for (const auto& b : g.blocks) if (b.start == s) return &b;
            return nullptr;
        };
        const BasicBlock* b0  = blockAt(mainVA);           // .. goto
        const BasicBlock* b13 = blockAt(mainVA + 13);      // nops
        const BasicBlock* b16 = blockAt(mainVA + 16);      // iconst_0 + tableswitch
        const BasicBlock* b40 = blockAt(mainVA + 40);      // return
        CHECK(b0 && b13 && b16 && b40);
        if (b0 && b13 && b16 && b40) {
            auto idxOf = [&](const BasicBlock* b) {
                return (size_t)(b - g.blocks.data());
            };
            CHECK(b0->isUncond);                           // goto recognized as unconditional
            CHECK(b0->succ.size() == 1 && b0->succ[0] == idxOf(b16));
            CHECK(b13->succ.size() == 1 && b13->succ[0] == idxOf(b16));   // fallthrough
            CHECK(b16->isSwitch);
            CHECK(b16->caseTargets.size() == 2);
            CHECK(b16->succ.size() == 2);                  // {16, 13}: deduped, no fallthrough to 40
            bool to16 = false, to13 = false, to40 = false;
            for (size_t s : b16->succ) {
                if (s == idxOf(b16)) to16 = true;
                if (s == idxOf(b13)) to13 = true;
                if (s == idxOf(b40)) to40 = true;
            }
            CHECK(to16 && to13 && !to40);
            CHECK(b40->isReturn);
        }
    }

    if (g_fail == 0) std::printf("ALL JVMDISASM TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
