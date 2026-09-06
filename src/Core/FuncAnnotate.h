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
#include "FunctionAnalyzer.h"
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
    Pattern         // suspicious/high-level pattern (sourceValid says instruction vs function scope)
};
const char* NoteKindName(NoteKind k);

// One annotation. `sourceValid` distinguishes instruction VA zero from a
// function-level finding; the numeric address is never a validity sentinel.
struct FnNote {
    uint64_t    va = 0;
    bool        sourceValid = false;
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

// A best-effort, machine-readable argument recovered at a named callsite.  The
// annotation UI still renders the compact text form, while higher-level passes
// (for example crackme network triage) can consume these fields without parsing
// prose.  Every validity bit is authoritative so address/immediate zero remains
// representable.
struct ApiArgumentObservation {
    uint32_t    index = 0;        // zero-based ABI argument position
    std::string abiLocation;      // rcx/rdx/r8/r9 or arg1/arg2/... for x86 pushes
    std::string parameter;        // bounded API-database name when known
    std::string renderedValue;    // analyst-facing recovered value
    uint64_t    referencedAddress = 0;
    bool        referencedAddressValid = false;
    uint64_t    immediate = 0;
    bool        immediateValid = false;
    std::string stringLiteral;    // resolver-proven string at referencedAddress
    bool        stringLiteralTruncated = false; // preview hit the 40-byte cap
    // Canonical best-effort source expression before display decoration.  This
    // keeps stack buffers such as [rbp - 0x80] and stable register aliases such
    // as rbx available to bounded reply-content data-flow consumers.
    std::string sourceExpression;
    // True only when the local producer proved address construction (for
    // example LEA or a direct address immediate). A bare register/memory load
    // may merely hold a pointer and must not be treated as output contents.
    bool        sourceIsAddress = false;
    float       confidence = 0.0f;
    std::string evidence;
};

// Bounded, local classification of the first observed use of a call's return
// register.  This is deliberately not full interprocedural data flow: the
// accompanying instruction/evidence tells higher-level consumers exactly what
// the annotation pass proved inside its short CFG window.
enum class ApiReturnUseKind : uint8_t {
    Unknown = 0,
    Ignored,       // overwritten before an observed read
    Compared,      // cmp/test consumes the result
    Branched,      // cmp/test followed by a conditional branch
    Stored,        // copied into memory
    Propagated,    // copied into another register/stack argument
    Consumed,      // arithmetic, indirect call, or another direct use
    Returned,      // enclosing function returns the callee result unchanged
};

const char* ApiReturnUseKindName(ApiReturnUseKind kind);

// Machine-readable summary of the value returned by the enclosing function.
// Unlike ApiReturnUseKind (which describes how one callee result is consumed),
// this classifies the ABI return register at every reachable return exit.  A
// function-level kind is published only when the CFG and every exit are
// understood; callers must check FunctionReturnObservation::complete.
enum class FunctionReturnKind : uint8_t {
    Unknown = 0,
    CanonicalBoolean,       // every possible value at every exit is exactly 0 or 1
    MaterializedCondition,  // SETcc-derived value, with a known valid low-bit width
    FieldBackedBoolean,     // byte/bool load from a proved formal-parameter field
    ForwardedCall,          // unchanged result of a named direct call
};

const char* FunctionReturnKindName(FunctionReturnKind kind);

// One reachable machine return. Numeric locations carry explicit validity so
// an image mapped at VA zero remains representable.
struct FunctionReturnExitObservation {
    uint64_t    returnVA = 0;
    bool        returnVAValid = false;
    FunctionReturnKind kind = FunctionReturnKind::Unknown;
    uint16_t    validWidthBits = 0;
    bool        validWidthKnown = false;

    uint64_t    constantValue = 0;
    bool        constantValueValid = false;

    // Link to the exact, unmerged access in FuncAnnotations::fieldAccesses.
    uint32_t    fieldAccessIndex = 0;
    bool        fieldAccessIndexValid = false;

    uint64_t    forwardedCallVA = 0;
    bool        forwardedCallVAValid = false;
    uint64_t    forwardedTargetVA = 0;
    bool        forwardedTargetVAValid = false;
    std::string forwardedName;

    bool        exact = false;
    float       confidence = 0.0f;
    std::string evidence;
};

struct FunctionReturnObservation {
    bool        analysisAttempted = false;
    bool        complete = false;
    FunctionReturnKind kind = FunctionReturnKind::Unknown;
    uint16_t    validWidthBits = 0;
    bool        validWidthKnown = false;
    std::vector<FunctionReturnExitObservation> exits;
    float       confidence = 0.0f;
    std::string evidence;
    std::string incompleteReason;
};

enum class ObjectFieldAccessKind : uint8_t {
    Read = 0,
    Write,
    ReadWrite,
};

const char* ObjectFieldAccessKindName(ObjectFieldAccessKind kind);

// One exact instruction operand rooted in a stable ABI formal parameter.  The
// identity is (functionVA, rootParameterIndex, displacement), never the offset
// alone. Observations intentionally remain per-access here; a whole-program
// consumer may merge them only after preserving that root identity.
struct ObjectFieldAccessObservation {
    uint64_t    functionVA = 0;
    bool        functionVAValid = false;
    uint64_t    instructionVA = 0;
    bool        instructionVAValid = false;
    uint32_t    operandIndex = 0;
    bool        operandIndexValid = false;
    uint32_t    rootParameterIndex = 0; // zero-based formal parameter
    bool        rootParameterIndexValid = false;
    std::string rootAbiLocation;        // rcx/rdx/r8/r9 for Microsoft x64
    int64_t     displacement = 0;
    bool        displacementValid = false;
    uint16_t    widthBits = 0;
    bool        widthKnown = false;
    ObjectFieldAccessKind access = ObjectFieldAccessKind::Read;
    bool        exact = false;
    float       confidence = 0.0f;
    std::string evidence;
};

// Exact interprocedural companion to ObjectFieldAccessObservation.  At one
// decoder-proved direct call to an adapter-classified internal function, this
// records that a callee formal receives an unchanged pointer rooted in one of
// the caller's ABI formals.  Bias is explicit: consumers must not assume that
// an absent or adjusted root denotes the same object base.
struct DirectCallFormalBindingObservation {
    uint64_t    callerFunctionVA = 0;
    bool        callerFunctionVAValid = false;
    uint32_t    callerRootParameterIndex = 0;
    bool        callerRootParameterIndexValid = false;
    std::string callerRootAbiLocation;
    int64_t     callerRootBias = 0;
    bool        callerRootBiasValid = false;

    uint64_t    callVA = 0;
    bool        callVAValid = false;
    uint64_t    calleeFunctionVA = 0;
    bool        calleeFunctionVAValid = false;
    uint32_t    calleeFormalParameterIndex = 0;
    bool        calleeFormalParameterIndexValid = false;
    std::string calleeAbiLocation;

    bool        directCallTargetExact = false;
    bool        argumentRootExact = false;
    float       confidence = 0.0f;
    std::string evidence;
};

// A comparison reached from a catalog-declared networking reply/output buffer.
// This is deliberately separate from ApiReturnUseKind: recv's EAX is a byte
// count and WinHttpReadData's EAX is a BOOL, while the accept/reject check
// normally consumes bytes written through an output argument.
enum class ApiReplyDecisionKind : uint8_t {
    DirectComparison = 0,
    ComparisonCall,
};

const char* ApiReplyDecisionKindName(ApiReplyDecisionKind kind);

struct ApiReplyDecisionObservation {
    ApiReplyDecisionKind kind = ApiReplyDecisionKind::DirectComparison;
    uint32_t    outputArgumentIndex = 0;
    std::string outputRole;
    std::string outputExpression;

    uint64_t    comparisonVA = 0;
    bool        comparisonVAValid = false;
    std::string comparisonInstruction;
    std::string comparisonSummary;
    std::string expectedValue;

    uint64_t    decisionVA = 0;
    bool        decisionVAValid = false;
    uint64_t    decisionTarget = 0;
    bool        decisionTargetValid = false;
    uint64_t    fallthroughVA = 0;
    bool        fallthroughVAValid = false;
    std::string decisionInstruction;
    std::string takenPathSummary;
    std::string fallthroughPathSummary;

    uint64_t    matchVA = 0;
    bool        matchVAValid = false;
    uint64_t    mismatchVA = 0;
    bool        mismatchVAValid = false;

    float       confidence = 0.0f;
    std::string evidence;
};

// A same-function decision reached from the fixed output argument of an exact
// cataloged local-input API (for example GetDlgItemTextA or fgets). This stays
// distinct from reply decisions: it proves only bounded local data flow from an
// input buffer into an exact comparator or inline cmp/test, never user intent or
// that the recovered branch is the program's final authorization gate.
enum class ApiLocalInputDecisionKind : uint8_t {
    DirectComparison = 0,
    ComparisonCall,
};

const char* ApiLocalInputDecisionKindName(ApiLocalInputDecisionKind kind);

struct ApiLocalInputDecisionObservation {
    ApiLocalInputDecisionKind kind = ApiLocalInputDecisionKind::DirectComparison;
    uint32_t    outputArgumentIndex = 0;
    std::string inputEncoding;
    std::string outputExpression;

    // Populated for ComparisonCall; empty/invalid for an inline cmp/test.
    std::string comparatorName;
    uint64_t    comparatorCallVA = 0;
    bool        comparatorCallVAValid = false;

    uint64_t    comparisonVA = 0;
    bool        comparisonVAValid = false;
    std::string comparisonInstruction;
    std::string comparisonSummary;
    std::string expectedValue;

    uint64_t    decisionVA = 0;
    bool        decisionVAValid = false;
    uint64_t    decisionTarget = 0;
    bool        decisionTargetValid = false;
    uint64_t    fallthroughVA = 0;
    bool        fallthroughVAValid = false;
    std::string decisionInstruction;
    std::string takenPathSummary;
    std::string fallthroughPathSummary;

    uint64_t    matchVA = 0;
    bool        matchVAValid = false;
    uint64_t    mismatchVA = 0;
    bool        mismatchVAValid = false;

    float       confidence = 0.0f;
    std::string evidence;
};

struct ApiCallObservation {
    uint64_t    callVA = 0;
    bool        callVAValid = false;
    uint64_t    targetVA = 0;
    bool        targetVAValid = false;
    std::string resolvedName;
    std::vector<ApiArgumentObservation> arguments;
    bool        returnValueUsed = false;
    bool        returnValueUseKnown = false;
    uint64_t    returnUseVA = 0;
    bool        returnUseVAValid = false;
    ApiReturnUseKind returnUseKind = ApiReturnUseKind::Unknown;
    std::string returnUseInstruction;
    std::string returnUseSummary;
    bool        resultInfluencesDecision = false;
    uint64_t    decisionVA = 0;
    bool        decisionVAValid = false;
    uint64_t    decisionTarget = 0;
    bool        decisionTargetValid = false;
    std::string decisionInstruction;
    std::string returnUseEvidence;
    float       returnUseConfidence = 0.0f;
    bool        replyDecisionAnalysisAttempted = false;
    bool        replyDecisionsComplete = true;
    std::string replyDecisionIncompleteReason;
    std::vector<ApiReplyDecisionObservation> replyDecisions;
    bool        localInputDecisionAnalysisAttempted = false;
    bool        localInputDecisionsComplete = true;
    std::string localInputDecisionIncompleteReason;
    std::vector<ApiLocalInputDecisionObservation> localInputDecisions;
    float       confidence = 0.0f;
    std::string evidence;
};

struct FuncAnnotations {
    bool complete = true;
    std::string incompleteReason;
    std::vector<FunctionChunk> chunks;
    bool ownershipTruncated = false;
    FunctionSeedKind seedKind = FunctionSeedKind::Prologue;
    FunctionBoundaryConfidence boundaryConfidence = FunctionBoundaryConfidence::Heuristic;
    // Function-level inference. All heuristic; convEvidence says why.
    std::string convention;       // "Microsoft x64", "stdcall (ret 0xN)", "thiscall? (ecx)", ...
    float       convConfidence = 0.0f;
    std::string convEvidence;
    std::vector<std::string> args;     // per-argument lines ("arg1 in rcx — used as struct pointer (+0x8, +0x10)")
    bool        hasFramePointer = false;
    uint32_t    frameBytes = 0;        // locals reserved by `sub rsp/esp, N` (0 = none seen)
    std::vector<StackSlot>   stack;    // de-duped frame slots, sorted by (base, offset)
    std::vector<RegLifetime> regs;     // register lifetimes (approximate)
    std::vector<ApiCallObservation> apiCalls; // typed named-call observations
    bool fieldAccessAnalysisAttempted = false;
    bool fieldAccessesComplete = false;
    std::string fieldAccessIncompleteReason;
    std::vector<ObjectFieldAccessObservation> fieldAccesses; // exact, unmerged formal-root accesses
    bool directCallFormalBindingAnalysisAttempted = false;
    bool directCallFormalBindingsComplete = false;
    std::string directCallFormalBindingIncompleteReason;
    std::vector<DirectCallFormalBindingObservation> directCallFormalBindings;
    FunctionReturnObservation returnObservation; // typed ABI return-value classification
    std::vector<FnNote>      notes;    // all notes, sorted by va (function-level first)
    std::string summary;               // compact one-liner for the function divider
    const char* analyzer = "FuncAnnotate";
};

struct AnnotateOptions {
    bool x64 = true;   // 64-bit conventions (Microsoft x64) vs 32-bit x86 (cdecl/stdcall/thiscall)
    std::vector<FunctionChunk> chunks;
    bool ownershipTruncated = false;
    FunctionSeedKind seedKind = FunctionSeedKind::Prologue;
    FunctionBoundaryConfidence boundaryConfidence = FunctionBoundaryConfidence::Heuristic;
    // Resolve a call target or IAT-slot VA to a display name ("kernel32.lstrcmpA",
    // "sub_401000"). "" = unknown.
    std::function<std::string(uint64_t)> nameFor;
    // Resolve a data VA to a short string literal living there ("" = none).
    std::function<std::string(uint64_t)> stringFor;
    // True if the data VA plausibly starts a vtable (consecutive code pointers).
    std::function<bool(uint64_t)> looksLikeVtable;
    // Exact membership classifier for internal function entries.  Formal-root
    // call bindings are not emitted when this is absent: a resolved import/API
    // target must never be invented as a callee object formal.
    std::function<bool(uint64_t)> isInternalFunction;
    // True only when false from isInternalFunction authoritatively excludes an
    // address from the analyzed internal-function scope. Positive exact rows
    // can still be emitted when false, but binding completeness remains false.
    bool internalFunctionMembershipComplete = false;
};

// Analyze one function's CFG (BuildCFG output) and return its annotations.
// Designed for x86/x64 Intel-syntax text; other arches get only the structural
// notes (loops/switches). Pure and deterministic.
FuncAnnotations AnnotateFunction(const ControlFlowGraph& g, const AnnotateOptions& opt = {});

} // namespace ds
