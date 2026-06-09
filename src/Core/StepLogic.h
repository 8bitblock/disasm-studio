#pragma once
//
// StepLogic.h
// Pure, side-effect-free decision logic for the single-step debugger engine.
//
// The Win32 debug loop (Debugger.cpp) is hard to unit-test because it requires a
// live debuggee. The *decisions* it makes while stepping, however, are pure
// functions of (a) what kind of instruction sits under the program counter and
// (b) which command the user issued. Those decisions are factored out here so
// they can be exercised by an off-target unit test (see tests/step_logic_test.cpp)
// with no dependency on Windows, Zydis, or a real process.
//
#include <cstdint>

namespace ds {

// How an instruction behaves for the purposes of stepping. Anything that is not
// a call, a return, or a REP-prefixed string op is "Normal" (including ordinary
// conditional/unconditional branches, which single-step cleanly to their target).
enum class InsnKind : uint8_t { Normal, Call, Ret, RepString };

inline InsnKind ClassifyInsn(bool isCall, bool isRet, bool isRepString) {
    if (isCall)      return InsnKind::Call;
    if (isRet)       return InsnKind::Ret;
    if (isRepString) return InsnKind::RepString;
    return InsnKind::Normal;
}

// ---- Step Over (thread is at a clean instruction boundary, not on a bp) ------
enum class StepOverAction : uint8_t {
    SingleStep,    // trap-flag exactly one instruction, then stop
    StepOverUnit   // a call or rep-string: set a temp bp after it and run, so the
                   // callee / the whole repeat executes without us tracing into it
};
inline StepOverAction DecideStepOver(InsnKind k) {
    return (k == InsnKind::Call || k == InsnKind::RepString)
        ? StepOverAction::StepOverUnit
        : StepOverAction::SingleStep;
}

// ---- Step Out (run until the current function returns) -----------------------
// Key idea: because we step *over* every call, the single-step trace never
// descends into callees, so the first `ret` we land on belongs to the current
// function. That makes step-out O(instructions in this frame) instead of
// O(instructions in this frame + all callees).
enum class StepOutAction : uint8_t {
    SingleStep,     // ordinary instruction: trap-flag one step, then re-evaluate
    StepOverUnit,   // call/rep: run over it (temp bp after) so we never descend
    FinishAfterRet  // a ret: let it execute; afterwards we have left the frame
};
inline StepOutAction DecideStepOut(InsnKind k) {
    switch (k) {
        case InsnKind::Call:
        case InsnKind::RepString: return StepOutAction::StepOverUnit;
        case InsnKind::Ret:       return StepOutAction::FinishAfterRet;
        case InsnKind::Normal:
        default:                  return StepOutAction::SingleStep;
    }
}

// ---- Resuming from a user breakpoint we are parked on ------------------------
// A software breakpoint overwrites the first byte of an instruction with 0xCC.
// To leave it we must: (1) restore the original byte, (2) execute the original
// instruction, (3) re-arm the 0xCC, and only then (4) realize the user's command.
// How we sequence (2)-(4) depends on the command and the instruction underneath.
enum class StepCmd : uint8_t { Continue, StepInto, StepOver, StepOut };

enum class ReArmMethod : uint8_t {
    SingleStep,   // trap-flag the original instruction; re-arm in the #DB handler
    TempBpAfter   // set a temp bp after the instruction and run (used to step OVER
                  // a call/rep that sits directly on the breakpoint)
};
enum class AfterReArm : uint8_t {
    Pause,           // stop and surface to the UI
    FreeRun,         // clear the trap flag and continue
    BeginStepOut,    // start a fresh step-out from the post-instruction RIP
    ContinueStepOut  // (TempBpAfter path) keep an already-running step-out going
};
struct OnBpResume { ReArmMethod method; AfterReArm after; };

inline OnBpResume DecideOnBpResume(StepCmd c, InsnKind k) {
    const bool unit = (k == InsnKind::Call || k == InsnKind::RepString);
    switch (c) {
        case StepCmd::Continue:
            return { ReArmMethod::SingleStep, AfterReArm::FreeRun };
        case StepCmd::StepInto:
            // One step off the breakpoint *is* a step-into (into the callee for a
            // call, to the branch target for a jump, to the next insn otherwise).
            return { ReArmMethod::SingleStep, AfterReArm::Pause };
        case StepCmd::StepOver:
            // Stepping a non-call by one instruction == stepping over it. A call or
            // rep must instead run to its return point via a temp breakpoint.
            return unit ? OnBpResume{ ReArmMethod::TempBpAfter, AfterReArm::Pause }
                        : OnBpResume{ ReArmMethod::SingleStep,  AfterReArm::Pause };
        case StepCmd::StepOut:
            // Sitting on the frame's own `ret`: stepping it leaves the frame.
            if (k == InsnKind::Ret)
                return { ReArmMethod::SingleStep, AfterReArm::Pause };
            // On a call/rep: run over it, then continue stepping out from after it.
            // On anything else: step it once, then begin stepping out.
            return unit ? OnBpResume{ ReArmMethod::TempBpAfter, AfterReArm::ContinueStepOut }
                        : OnBpResume{ ReArmMethod::SingleStep,  AfterReArm::BeginStepOut };
    }
    return { ReArmMethod::SingleStep, AfterReArm::FreeRun };
}

// What a one-shot temporary breakpoint is standing in for when it fires. Shared
// between the debug loop and tests.
enum class TempKind : uint8_t {
    None,
    RunTo,        // user "run to cursor" target
    StepOver,     // return point of a stepped-over call/rep -> pause
    StepOutSkip,  // return point of a call/rep skipped during step-out -> keep going
    EntryPoint    // launch break-at-entry: one-shot bp at the program entry -> pause
};

} // namespace ds
