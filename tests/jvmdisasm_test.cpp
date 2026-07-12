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

#include <cstdio>
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

        CHECK(insns[1].isCall && insns[1].isBranch);
        CHECK(insns[1].branchTarget == helperVA);          // LOCAL method resolved
        CHECK(insns[1].comment == "Main.helper:()I");

        CHECK(insns[2].operands == "7");                   // bipush
        CHECK(insns[3].operands == "1, 1");                // iinc

        CHECK(insns[4].isBranch && !insns[4].isCall && !insns[4].isRet);
        CHECK(insns[4].branchTarget == mainVA + 16);       // goto

        const Instruction& sw = insns[9];                  // tableswitch @ bci 17, pad 2
        CHECK(sw.address == mainVA + 17);
        CHECK(sw.isBranch && !sw.isCall);
        CHECK(sw.branchTarget == mainVA + 13);             // default
        CHECK(sw.extraTargets.size() == 2);
        if (sw.extraTargets.size() == 2) {
            CHECK(sw.extraTargets[0] == mainVA + 16);      // case 0
            CHECK(sw.extraTargets[1] == mainVA + 13);      // case 1
        }
        CHECK(sw.operands.find("0..1") != std::string::npos);

        CHECK(insns[10].isRet);                            // return
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

    // A resolved target of zero is distinct from an unresolved branch. This is
    // the decoder-level contract used by raw mappings based at VA 0.
    {
        JvmDisassembler bare;
        const uint8_t goZero[] = { 0xA7, 0xFF, 0xFD }; // goto -3, decoded at VA 3
        Instruction in;
        CHECK(bare.decodeOne(goZero, sizeof(goZero), 3, in));
        CHECK(in.mnemonic == "goto" && in.branchTarget == 0 && HasBranchTarget(in));

        const uint8_t loopToZero[] = { 0x00, 0x00, 0x00, 0xA7, 0xFF, 0xFD };
        ControlFlowGraph g = BuildCFG(loopToZero, sizeof(loopToZero), 0, bare, 32);
        size_t zeroBlock = g.blocks.size(), jumpBlock = g.blocks.size();
        for (size_t i = 0; i < g.blocks.size(); ++i) {
            if (g.blocks[i].start == 0) zeroBlock = i;
            if (g.blocks[i].start == 3) jumpBlock = i;
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
            CHECK(v[0].extraTargets.size() == 2);
            if (v[0].extraTargets.size() == 2) {
                CHECK(v[0].extraTargets[0] == 0x14 && v[0].extraTargets[1] == 0x18);
            }
            CHECK(v[0].comment.find("5 -> 0x14") != std::string::npos);
        }
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
