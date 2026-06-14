#pragma once
//
// FuncAnnotate.h
// Per-function annotation engine for x86/x64: given one function's CFG it
// infers (heuristically, with evidence) the prologue/epilogue, calling
// convention, arguments, stack-frame layout and locals, register lifetimes,
// whether each call's return value is checked, plain-language conditional
// branch meaning ("jumps if rax == 0; return value of strcmp controls this
// branch"), loops, switch tables, indirect/virtual calls, this-pointer and
// vtable usage, and suspicious high-level patterns (XOR decode loops,
// checksum/hash loops, string comparison, input reading, file/config loading,
// networking, timers, message/update loops, callback registration).
//
// Honesty contract: every finding carries a confidence score (0..1), an
// evidence string explaining WHY, and the analyzer name. Nothing here is a
// fact — the UI must render these as annotated guesses (and does).
//
// Pure logic: no ImGui / Win32 / engine includes, so it compiles and
// unit-tests in isolation exactly like Decompiler/DataFlow/TechScan
// (tests/funcannotate_test.cpp).
//
#include "CFG.h"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

enum class NoteKind : uint8_t {
    Prologue,       // frame setup instruction (push rbp / mov rbp,rsp / sub rsp,N / save callee-saved)
    Epilogue,       // frame teardown before ret
    Branch,         // conditional branch meaning in plain language
    Loop,           // loop header / back edge ("loop continues while ...")
    Switch,         // jump-table dispatch
    Call,           // direct call: purpose + sniffed argument values
    IndirectCall,   // call through a register / computed memory
    VirtualCall,    // vtable-slot call pattern (obj -> vtable -> slot)
    Vtable,         // vtable pointer store (object construction?)
    RetUse,         // whether a call's return value is checked/used
    Pattern         // function-level suspicious/high-level pattern (va = 0)
};
const char* NoteKindName(NoteKind k);

// One annotation: attaches to an instruction VA (0 = whole function).
struct FnNote {
    uint64_t    va = 0;
    NoteKind    kind = NoteKind::Pattern;
    std::string text;             // plain-language annotation (rendered inline)
    std::string evidence;         // why: the instructions/APIs/strings backing it
    float       confidence = 0.5f;// 0..1 heuristic score — never presented as fact
};

// One stack-frame slot (local variable or stack-passed argument).
struct StackSlot {
    std::string base;             // frame register the access went through ("rbp"/"rsp"/...)
    int64_t     offset = 0;       // signed displacement from that base
    bool        isArg = false;    // above the return address (caller-pushed / home slot)
    int         reads = 0, writes = 0;
    std::string name;             // var_8 / arg_0 style display name
};

// Approximate (linear-scan, address order) lifetime of one register family.
struct RegLifetime {
    std::string reg;              // canonical 64-bit family name ("rax", "r8", ...)
    uint64_t    firstVA = 0;      // first write (or first read if never written)
    uint64_t    lastVA  = 0;      // last access seen
    int         reads = 0, writes = 0;
};

struct FuncAnnotations {
    // Function-level inference. All heuristic; convEvidence says why.
    std::string convention;       // "Microsoft x64", "stdcall (ret 0xN)", "thiscall? (ecx)", ...
    float       convConfidence = 0.0f;
    std::string convEvidence;
    std::vector<std::string> args;     // per-argument lines ("arg1 in rcx — used as struct pointer (+0x8, +0x10)")
    bool        hasFramePointer = false;
    uint32_t    frameBytes = 0;        // locals reserved by `sub rsp/esp, N` (0 = none seen)
    std::vector<StackSlot>   stack;    // de-duped frame slots, sorted by (base, offset)
    std::vector<RegLifetime> regs;     // register lifetimes (approximate)
    std::vector<FnNote>      notes;    // all notes, sorted by va (function-level first)
    std::string summary;               // compact one-liner for the function divider
    const char* analyzer = "FuncAnnotate";
};

struct AnnotateOptions {
    bool x64 = true;   // 64-bit conventions (Microsoft x64) vs 32-bit x86 (cdecl/stdcall/thiscall)
    // Resolve a call target or IAT-slot VA to a display name ("kernel32.lstrcmpA",
    // "sub_401000"). "" = unknown.
    std::function<std::string(uint64_t)> nameFor;
    // Resolve a data VA to a short string literal living there ("" = none).
    std::function<std::string(uint64_t)> stringFor;
    // True if the data VA plausibly starts a vtable (consecutive code pointers).
    std::function<bool(uint64_t)> looksLikeVtable;
};

// Analyze one function's CFG (BuildCFG output) and return its annotations.
// Designed for x86/x64 Intel-syntax text; other arches get only the structural
// notes (loops/switches). Pure and deterministic.
FuncAnnotations AnnotateFunction(const ControlFlowGraph& g, const AnnotateOptions& opt = {});

} // namespace ds
