//
// step_logic_test.cpp
// Off-target unit + simulation test for src/Core/StepLogic.h.
//
// The Win32 debug loop cannot run here, but its *decisions* are pure functions.
// This test (1) pins the decision tables and (2) runs a tiny synthetic CPU whose
// step-out / step-over follow exactly the same decisions the debugger makes,
// proving they land on the correct instruction across nested calls.
//
// Build & run (Linux/macOS):  g++ -std=c++20 -I../src tests/step_logic_test.cpp && ./a.out
//
#include "Core/StepLogic.h"
#include "Core/DebuggerExecutionPolicy.h"
#include <cstdio>
#include <cstdint>
#include <vector>
#include <string>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// ----------------------------------------------------------------------------
// 1) Decision tables
// ----------------------------------------------------------------------------
static void test_classify() {
    CHECK(ClassifyInsn(true,  false, false) == InsnKind::Call);
    CHECK(ClassifyInsn(false, true,  false) == InsnKind::Ret);
    CHECK(ClassifyInsn(false, false, true ) == InsnKind::RepString);
    CHECK(ClassifyInsn(false, false, false) == InsnKind::Normal);
    // Call takes priority if a (nonsensical) multi-flag ever occurs.
    CHECK(ClassifyInsn(true,  true,  true ) == InsnKind::Call);
}

static void test_step_over() {
    CHECK(DecideStepOver(InsnKind::Call)      == StepOverAction::StepOverUnit);
    CHECK(DecideStepOver(InsnKind::RepString) == StepOverAction::StepOverUnit);
    CHECK(DecideStepOver(InsnKind::Ret)       == StepOverAction::SingleStep);
    CHECK(DecideStepOver(InsnKind::Normal)    == StepOverAction::SingleStep);
}

static void test_step_out() {
    CHECK(DecideStepOut(InsnKind::Call)      == StepOutAction::StepOverUnit);
    CHECK(DecideStepOut(InsnKind::RepString) == StepOutAction::StepOverUnit);
    CHECK(DecideStepOut(InsnKind::Ret)       == StepOutAction::FinishAfterRet);
    CHECK(DecideStepOut(InsnKind::Normal)    == StepOutAction::SingleStep);
}

static void test_on_bp_resume() {
    // Continue: always single-step the original instruction then free-run.
    for (auto k : {InsnKind::Normal, InsnKind::Call, InsnKind::Ret, InsnKind::RepString}) {
        auto p = DecideOnBpResume(StepCmd::Continue, k);
        CHECK(p.method == ReArmMethod::SingleStep && p.after == AfterReArm::FreeRun);
    }
    // StepInto: single-step then pause, regardless of instruction.
    for (auto k : {InsnKind::Normal, InsnKind::Call, InsnKind::Ret, InsnKind::RepString}) {
        auto p = DecideOnBpResume(StepCmd::StepInto, k);
        CHECK(p.method == ReArmMethod::SingleStep && p.after == AfterReArm::Pause);
    }
    // StepOver: call/rep must run-over via a temp bp; everything else single-steps.
    {
        auto call = DecideOnBpResume(StepCmd::StepOver, InsnKind::Call);
        CHECK(call.method == ReArmMethod::TempBpAfter && call.after == AfterReArm::Pause);
        auto rep  = DecideOnBpResume(StepCmd::StepOver, InsnKind::RepString);
        CHECK(rep.method == ReArmMethod::TempBpAfter && rep.after == AfterReArm::Pause);
        auto norm = DecideOnBpResume(StepCmd::StepOver, InsnKind::Normal);
        CHECK(norm.method == ReArmMethod::SingleStep && norm.after == AfterReArm::Pause);
        auto ret  = DecideOnBpResume(StepCmd::StepOver, InsnKind::Ret);
        CHECK(ret.method == ReArmMethod::SingleStep && ret.after == AfterReArm::Pause);
    }
    // StepOut: ret -> pause; call/rep -> run-over then keep stepping out;
    //          normal -> single-step then begin a fresh step-out.
    {
        auto ret  = DecideOnBpResume(StepCmd::StepOut, InsnKind::Ret);
        CHECK(ret.method == ReArmMethod::SingleStep && ret.after == AfterReArm::Pause);
        auto call = DecideOnBpResume(StepCmd::StepOut, InsnKind::Call);
        CHECK(call.method == ReArmMethod::TempBpAfter && call.after == AfterReArm::ContinueStepOut);
        auto rep  = DecideOnBpResume(StepCmd::StepOut, InsnKind::RepString);
        CHECK(rep.method == ReArmMethod::TempBpAfter && rep.after == AfterReArm::ContinueStepOut);
        auto norm = DecideOnBpResume(StepCmd::StepOut, InsnKind::Normal);
        CHECK(norm.method == ReArmMethod::SingleStep && norm.after == AfterReArm::BeginStepOut);
    }
}

// ----------------------------------------------------------------------------
// 2) Synthetic CPU + stack. Each instruction is one "address" (index). The
//    simulator drives stepping using ONLY the StepLogic decisions, mirroring the
//    debugger's loop: step-over a call == run the callee to its return point
//    without tracing into it; finish-after-ret == execute the ret and stop.
// ----------------------------------------------------------------------------
struct Insn { InsnKind kind; int target; }; // target used for Call/Branch
struct CPU {
    std::vector<Insn>     prog;
    std::vector<int>      stack;   // return addresses
    int pc = 0;

    // Execute exactly one instruction (the real CPU effect), updating pc/stack.
    void execOne() {
        const Insn& in = prog[pc];
        switch (in.kind) {
            case InsnKind::Call:
                stack.push_back(pc + 1); pc = in.target;
                break;
            case InsnKind::Ret:
                if (stack.empty()) { pc = -1; }
                else { pc = stack.back(); stack.pop_back(); }
                break;
            case InsnKind::Normal:    // a Normal may be a static branch if target>=0
            case InsnKind::RepString:
                pc = (in.target >= 0) ? in.target : pc + 1;
                break;
        }
    }
    // Run freely until pc reaches `until` (models temp-bp-after-call + continue).
    void runUntil(int until, int guard = 100000) {
        while (pc != until && guard-- > 0) execOne();
    }
};

// Simulate STEP OUT starting at the current pc. Returns the pc we stop on.
static int simStepOut(CPU& cpu) {
    for (int guard = 0; guard < 100000; ++guard) {
        InsnKind k = cpu.prog[cpu.pc].kind;
        switch (DecideStepOut(k)) {
            case StepOutAction::StepOverUnit: {
                int ret = cpu.pc + 1;            // temp bp at the return point
                cpu.execOne();                   // execute the call/rep
                cpu.runUntil(ret);               // run callee to completion
                break;                           // ...then re-evaluate at `ret`
            }
            case StepOutAction::FinishAfterRet:
                cpu.execOne();                   // execute the ret -> now in caller
                return cpu.pc;                   // stop (debugger pauses here)
            case StepOutAction::SingleStep:
                cpu.execOne();
                break;
        }
    }
    return -2; // cap/over-run sentinel
}

// Simulate STEP OVER of the instruction at the current pc. Returns stop pc.
static int simStepOver(CPU& cpu) {
    InsnKind k = cpu.prog[cpu.pc].kind;
    if (DecideStepOver(k) == StepOverAction::StepOverUnit) {
        int ret = cpu.pc + 1;
        cpu.execOne();
        cpu.runUntil(ret);
        return cpu.pc;            // == ret
    }
    cpu.execOne();                // single-step a normal/branch/ret
    return cpu.pc;
}

// A small program with a caller, funcA, and funcB (funcA calls funcB).
//  idx kind          meaning
//   0  Normal        caller: prologue
//   1  Call -> 3     caller: call funcA   (return point = 2)
//   2  Normal        caller: after the call      <-- step-out target
//   3  Normal        funcA: entry
//   4  Call -> 7     funcA: call funcB    (return point = 5)
//   5  Normal        funcA: more work
//   6  Ret           funcA: return -> 2
//   7  Normal        funcB: entry
//   8  Ret           funcB: return -> 5
static std::vector<Insn> nestedProg() {
    return {
        {InsnKind::Normal,-1}, {InsnKind::Call,3}, {InsnKind::Normal,-1},
        {InsnKind::Normal,-1}, {InsnKind::Call,7}, {InsnKind::Normal,-1}, {InsnKind::Ret,-1},
        {InsnKind::Normal,-1}, {InsnKind::Ret,-1},
    };
}

static void test_sim_step_out_nested() {
    CPU cpu; cpu.prog = nestedProg();
    cpu.pc = 3; cpu.stack = {2};         // stopped at funcA entry, called from idx 1
    int stop = simStepOut(cpu);
    CHECK(stop == 2);                    // step-out lands at the caller's return site
    CHECK(cpu.stack.empty());            // funcA's frame was unwound exactly once
}

static void test_sim_step_out_from_deeper() {
    CPU cpu; cpu.prog = nestedProg();
    cpu.pc = 5; cpu.stack = {2};         // funcA, just past its call to funcB
    int stop = simStepOut(cpu);
    CHECK(stop == 2);
    CHECK(cpu.stack.empty());
}

static void test_sim_step_over_call() {
    CPU cpu; cpu.prog = nestedProg();
    cpu.pc = 1; cpu.stack = {};          // on the caller's "call funcA"
    int stop = simStepOver(cpu);
    CHECK(stop == 2);                    // step-over skips the whole funcA+funcB subtree
    CHECK(cpu.stack.empty());
}

static void test_sim_step_over_normal() {
    CPU cpu; cpu.prog = { {InsnKind::Normal,-1}, {InsnKind::Normal,-1} };
    cpu.pc = 0;
    int stop = simStepOver(cpu);
    CHECK(stop == 1);                    // one instruction forward
}

static void test_sim_step_out_one_level() {
    // Two stack frames of the SAME function on the stack (as in recursion). Step-out
    // must unwind EXACTLY one level: to the inner return site (5), leaving the outer
    // frame's return (2) intact. (No infinite recursion: the traced frame just rets.)
    CPU cpu; cpu.prog = {
        {InsnKind::Normal,-1}, {InsnKind::Call,3}, {InsnKind::Normal,-1},
        {InsnKind::Normal,-1}, {InsnKind::Ret,-1},          // funcR: entry, then return
        {InsnKind::Normal,-1},                              // 5: inner return site
    };
    cpu.pc = 3; cpu.stack = {2, 5};      // outer ret=2 (caller), inner ret=5
    int stop = simStepOut(cpu);
    CHECK(stop == 5);                    // returns one level, to the inner call site
    CHECK(cpu.stack.size() == 1 && cpu.stack[0] == 2);
}

static void test_checked_execution_policy() {
    using namespace debugger_detail;
    uint32_t flags = 0x202;
    size_t writes = 0;
    const auto read = [&](uint32_t& out) { out = flags; return true; };
    const auto write = [&](uint32_t value) { flags = value; ++writes; return true; };
    CHECK(UpdateControlBits(0x100, true, read, write) == ControlMutationResult::Applied);
    CHECK(flags == 0x302 && writes == 1);
    CHECK(UpdateControlBits(0x100, true, read, write) == ControlMutationResult::Applied);
    CHECK(writes == 1); // already-correct state does not need a native write
    CHECK(UpdateControlBits(0x100, false, read, write) == ControlMutationResult::Applied);
    CHECK(flags == 0x202);
    CHECK(UpdateControlBits(0x100, true, [](uint32_t&) { return false; }, write) ==
          ControlMutationResult::ReadFailed);
    CHECK(flags == 0x202);

    writes = 0;
    const auto partialFailure = [&](uint32_t value) {
        flags = value; ++writes; return writes != 1;
    };
    CHECK(UpdateControlBits(0x100, true, read, partialFailure) == ControlMutationResult::WriteFailed);
    CHECK(flags == 0x202 && writes == 2); // a failing API may have changed the context
    writes = 0;
    const auto lostWrite = [&](uint32_t value) {
        ++writes;
        if (writes == 1) flags ^= 0x40; // preserve an unrelated flag during rollback
        else flags = value;
        return true;
    };
    CHECK(UpdateControlBits(0x100, true, read, lostWrite) == ControlMutationResult::VerifyFailed);
    CHECK(flags == 0x242);
    CHECK(UpdateControlBits(0x100, true, read, [](uint32_t) { return false; }) ==
          ControlMutationResult::RollbackFailed);

    CHECK(ValidHardwareBreakpoint(0x1001, true, 8, true)); // execute normalized to one byte
    CHECK(ValidHardwareBreakpoint(0x1000, false, 8, false));
    CHECK(!ValidHardwareBreakpoint(0x1000, false, 8, true));
    CHECK(!ValidHardwareBreakpoint(0x1001, false, 2, false));
    CHECK(!ValidHardwareBreakpoint(0x1000, false, 3, false));
    CHECK(!ValidHardwareBreakpoint(0x100000000ULL, true, 1, true));
    CHECK(!ValidHardwareBreakpoint(UINT64_MAX, false, 8, false));
    uint64_t continuation = 0;
    CHECK(CheckedInstructionContinuation(0x1000, 5, true, false, continuation));
    CHECK(continuation == 0x1005);
    CHECK(!CheckedInstructionContinuation(0x1000, 1, false, false, continuation));
    CHECK(!CheckedInstructionContinuation(UINT64_MAX - 2, 5, true, false, continuation));
    CHECK(!CheckedInstructionContinuation(UINT32_MAX - 2, 5, true, true, continuation));
    CHECK(!CheckedInstructionContinuation(0, 16, true, false, continuation));
}

int main() {
    test_checked_execution_policy();
    test_classify();
    test_step_over();
    test_step_out();
    test_on_bp_resume();
    test_sim_step_out_nested();
    test_sim_step_out_from_deeper();
    test_sim_step_over_call();
    test_sim_step_over_normal();
    test_sim_step_out_one_level();

    if (g_fail == 0) std::printf("ALL STEP-LOGIC TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
