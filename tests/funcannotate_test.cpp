//
// funcannotate_test.cpp
// Unit test for the per-function annotation engine (src/Core/FuncAnnotate.cpp).
// A MockDisassembler replays canned x86/x64 instruction streams; we BuildCFG +
// AnnotateFunction and assert the inferred convention/frame/branch/loop/call
// annotations (and that everything carries confidence + evidence).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\funcannotate_test.cpp ^
//      src\Core\FuncAnnotate.cpp src\Core\CFG.cpp
//   .\funcannotate_test.exe
//
#include "Core/CFG.h"
#include "Core/FuncAnnotate.h"
#include "Core/ApiInfo.h"
#include "Core/BranchComment.h"
#include "Disasm/IDisassembler.h"

#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

struct MockDisassembler : IDisassembler {
    std::unordered_map<uint64_t, Instruction> at;
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "mock"; }
    bool decodeOne(const uint8_t*, size_t, uint64_t va, Instruction& out) override {
        auto it = at.find(va); if (it == at.end()) return false; out = it->second; return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* d, size_t n, uint64_t va, size_t maxI) override {
        std::vector<Instruction> v; uint64_t a = va;
        while (!maxI || v.size() < maxI) { Instruction in; if (!decodeOne(d, n, a, in) || !in.length) break; v.push_back(in); a += in.length; }
        return v;
    }
};

static Instruction mk(uint64_t addr, uint32_t len, const char* mnem, const char* ops,
                      bool branch = false, bool ret = false, uint64_t target = 0) {
    Instruction in;
    in.address = addr; in.length = len; in.mnemonic = mnem; in.operands = ops;
    in.isCall = (std::string(mnem) == "call");
    in.isBranch = branch || in.isCall; in.isRet = ret; in.branchTarget = target;
    return in;
}

static TypedOperand regOp(const char* name, OperandAccess access,
                          uint16_t widthBits = 64) {
    TypedOperand operand;
    operand.kind = OperandKind::Register;
    operand.access = access;
    operand.widthBits = widthBits;
    operand.registerName = name;
    return operand;
}

static TypedOperand memOp(const char* base, int64_t displacement,
                          OperandAccess access, uint16_t widthBits = 64) {
    TypedOperand operand;
    operand.kind = OperandKind::Memory;
    operand.access = access;
    operand.widthBits = widthBits;
    operand.baseRegister = base;
    operand.displacement = displacement;
    operand.displacementValid = true;
    return operand;
}

static TypedOperand immOp(uint64_t value, uint16_t widthBits = 32) {
    TypedOperand operand;
    operand.kind = OperandKind::Immediate;
    operand.access = OperandAccess::Read;
    operand.widthBits = widthBits;
    operand.immediate = value;
    return operand;
}

static FuncAnnotations annotate(const std::vector<Instruction>& ins, AnnotateOptions opt = {}) {
    MockDisassembler dis;
    uint64_t base = ins.front().address;
    uint64_t end  = ins.back().address + ins.back().length;
    for (auto& in : ins) dis.at[in.address] = in;
    std::vector<uint8_t> buf((size_t)(end - base) + 16, 0);
    ControlFlowGraph g = BuildCFG(buf.data(), buf.size(), base, dis, 2000);
    return AnnotateFunction(g, opt);
}

// Exact single-block fixture for analyses whose honesty contract depends on a
// complete CFG. The general helper above deliberately gives BuildCFG trailing
// undecodable bytes so legacy partial-CFG behavior remains covered.
static FuncAnnotations annotateCompleteBlock(const std::vector<Instruction>& ins,
                                             AnnotateOptions opt = {}) {
    ControlFlowGraph graph;
    graph.funcStart = ins.front().address;
    BasicBlock block;
    block.start = ins.front().address;
    block.end = ins.back().address + ins.back().length;
    block.insns = ins;
    block.transferIndex = ins.size() - 1;
    block.isReturn = InstructionIsReturn(ins.back());
    graph.blocks.push_back(std::move(block));
    graph.decodedInstructions = ins.size();
    graph.decodedBytes = static_cast<size_t>(graph.blocks.front().end - graph.funcStart);
    return AnnotateFunction(graph, opt);
}

static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }

// First note of a kind whose text contains `sub` ("" = any text).
static const FnNote* findNote(const FuncAnnotations& a, NoteKind k, const char* sub = "") {
    for (const FnNote& n : a.notes)
        if (n.kind == k && (!*sub || has(n.text, sub))) return &n;
    return nullptr;
}

static const ApiCallObservation* findCall(const FuncAnnotations& a, uint64_t callVA) {
    for (const ApiCallObservation& call : a.apiCalls)
        if (call.callVAValid && call.callVA == callVA) return &call;
    return nullptr;
}

static const DirectCallFormalBindingObservation* findFormalBinding(
    const FuncAnnotations& annotations, uint64_t callVA,
    uint32_t calleeFormal) {
    for (const auto& binding : annotations.directCallFormalBindings) {
        if (binding.callVAValid && binding.callVA == callVA &&
            binding.calleeFormalParameterIndexValid &&
            binding.calleeFormalParameterIndex == calleeFormal)
            return &binding;
    }
    return nullptr;
}

int main() {
    // Static branch comments describe alternatives, never a live outcome.
    {
        Instruction branch = mk(0x1000, 2, "jne", "0x1010", true, false, 0x1010);
        CHECK(StaticBranchComment(branch, Arch::X64) ==
              "jumps if zero flag is clear; otherwise falls through");
        branch.mnemonic = "JNZ";
        CHECK(StaticBranchComment(branch, Arch::X86) ==
              "jumps if zero flag is clear; otherwise falls through");
        branch.mnemonic = "jcxz";
        CHECK(StaticBranchComment(branch, Arch::X86_16) ==
              "jumps if CX is zero; otherwise falls through");
        branch.mnemonic = "loop";
        CHECK(StaticBranchComment(branch, Arch::X86).find("rcx") == std::string::npos);
        CHECK(has(StaticBranchComment(branch, Arch::X86), "decremented loop counter"));
        branch.mnemonic = "jmp";
        branch.branchTarget = 0;
        branch.branchTargetValid = true;
        CHECK(StaticBranchComment(branch, Arch::X64) == "jumps to 0x0");
        branch.branchTargetValid = false;
        CHECK(StaticBranchComment(branch, Arch::X64) == "jumps to the branch target");
        branch.flow.kind = FlowKind::DirectCall;
        CHECK(StaticBranchComment(branch, Arch::X64).empty());
        branch.flow.kind = FlowKind::Return;
        CHECK(StaticBranchComment(branch, Arch::X64).empty());
        branch.flow.kind = FlowKind::Switch;
        CHECK(StaticBranchComment(branch, Arch::X64).empty());
        branch.flow.kind = FlowKind::ConditionalBranch;
        branch.mnemonic = "bne";
        branch.flow.delaySlots = 1;
        const std::string mips = StaticBranchComment(branch, Arch::MIPS);
        CHECK(has(mips, "jumps if its condition is true; otherwise falls through"));
        CHECK(has(mips, "delay-slot rules apply"));
        CHECK(mips.find("flag") == std::string::npos);
        branch.flow.kind = FlowKind::UnconditionalBranch;
        branch.flow.directTarget = 0x2468;
        branch.flow.directTargetValid = true;
        branch.flow.delaySlots = 0;
        CHECK(StaticBranchComment(branch, Arch::ARM64) == "jumps to 0x2468");
        CHECK(ConditionalBranchComment("value is zero", "0x0") ==
              "jumps to 0x0 if value is zero; otherwise falls through");
    }
    // 1) Prologue / frame pointer / frame size + epilogue, and the honesty contract
    //    (every note has evidence and an in-range confidence).
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 1, "push", "rbp"),
            mk(0x1001, 3, "mov",  "rbp, rsp"),
            mk(0x1004, 4, "sub",  "rsp, 0x40"),
            mk(0x1008, 4, "mov",  "qword ptr [rbp - 8], rcx"),
            mk(0x100C, 4, "mov",  "rax, qword ptr [rbp - 8]"),
            mk(0x1010, 1, "leave", ""),
            mk(0x1011, 1, "ret",  "", true, true),
        });
        CHECK(a.hasFramePointer);
        CHECK(a.frameBytes == 0x40);
        CHECK(findNote(a, NoteKind::Prologue, "frame pointer") != nullptr);
        CHECK(findNote(a, NoteKind::Prologue, "0x40") != nullptr);
        CHECK(findNote(a, NoteKind::Epilogue) != nullptr);
        // var_8: one write (store of rcx), one read (reload).
        bool foundLocal = false;
        for (const StackSlot& s : a.stack)
            if (!s.isArg && s.offset == -8) { foundLocal = true; CHECK(s.writes == 1); CHECK(s.reads == 1); CHECK(has(s.name, "var_8")); }
        CHECK(foundLocal);
        // rcx read before write -> Microsoft x64 arg evidence.
        CHECK(has(a.convention, "Microsoft x64"));
        CHECK(a.convConfidence > 0.4f && a.convConfidence < 1.0f);
        CHECK(!a.convEvidence.empty());
        CHECK(!a.args.empty() && has(a.args[0], "rcx"));
        for (const FnNote& n : a.notes) {
            CHECK(!n.evidence.empty());
            CHECK(n.confidence > 0.0f && n.confidence <= 1.0f);
        }
        CHECK(!a.summary.empty());
    }

    // 2) x86-32 stdcall via `ret imm` + stack args.
    {
        AnnotateOptions o; o.x64 = false;
        FuncAnnotations a = annotate({
            mk(0x1000, 1, "push", "ebp"),
            mk(0x1001, 2, "mov",  "ebp, esp"),
            mk(0x1003, 3, "mov",  "eax, dword ptr [ebp + 8]"),
            mk(0x1006, 3, "add",  "eax, dword ptr [ebp + 0xC]"),
            mk(0x1009, 1, "pop",  "ebp"),
            mk(0x100A, 3, "ret",  "0x8", true, true),
        }, o);
        CHECK(has(a.convention, "stdcall"));
        CHECK(has(a.convention, "0x8"));
        CHECK(a.convConfidence >= 0.8f);
        CHECK(has(a.convEvidence, "ret 0x8"));
        int args = 0;
        for (const StackSlot& s : a.stack) if (s.isArg) ++args;
        CHECK(args == 2);   // [ebp+8] and [ebp+0xC]
    }

    // 3) Branch meaning in plain language (cmp + jl, signed).
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "cmp", "eax, 0x10"),
            mk(0x1003, 2, "jl",  "0x100A", true, false, 0x100A),
            mk(0x1005, 5, "mov", "eax, 1"),
            mk(0x100A, 1, "ret", "", true, true),
        });
        const FnNote* n = findNote(a, NoteKind::Branch);
        CHECK(n != nullptr);
        if (n) {
            CHECK(has(n->text, "jumps to 0x100A"));
            CHECK(has(n->text, "eax < 0x10"));
            CHECK(has(n->text, "signed"));
            CHECK(has(n->text, "otherwise falls through"));
            CHECK(has(n->evidence, "cmp eax, 0x10"));
        }
    }

    // 4) strcmp-style call: result checked, and the branch explained in
    //    success/failure language ("Jumps ... if strcmp result is non-zero").
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) { return va == 0x2000 ? std::string("msvcrt.strcmp") : std::string(); };
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 2, "test", "eax, eax"),
            mk(0x1007, 2, "jne",  "0x1010", true, false, 0x1010),
            mk(0x1009, 5, "mov",  "eax, 1"),
            mk(0x100E, 1, "ret",  "", true, true),
            mk(0x1010, 1, "ret",  "", true, true),
        }, o);
        const FnNote* ru = findNote(a, NoteKind::RetUse);
        CHECK(ru != nullptr);
        if (ru) CHECK(has(ru->text, "checked"));
        CHECK(a.apiCalls.size() == 1);
        if (a.apiCalls.size() == 1) {
            CHECK(a.apiCalls[0].returnValueUseKnown);
            CHECK(a.apiCalls[0].returnValueUsed);
            CHECK(a.apiCalls[0].returnUseVAValid && a.apiCalls[0].returnUseVA == 0x1005);
            CHECK(a.apiCalls[0].returnUseKind == ApiReturnUseKind::Branched);
            CHECK(a.apiCalls[0].resultInfluencesDecision);
            CHECK(a.apiCalls[0].decisionVAValid && a.apiCalls[0].decisionVA == 0x1007);
            CHECK(a.apiCalls[0].decisionTargetValid && a.apiCalls[0].decisionTarget == 0x1010);
            CHECK(has(a.apiCalls[0].decisionInstruction, "jne"));
            CHECK(!a.apiCalls[0].returnUseEvidence.empty());
        }
        const FnNote* br = findNote(a, NoteKind::Branch);
        CHECK(br != nullptr);
        if (br) {
            CHECK(has(br->text, "strcmp"));
            CHECK(has(br->text, "non-zero"));
            CHECK(has(br->text, "differ"));
            CHECK(has(br->text, "otherwise falls through"));
        }
        // Function-level pattern: performs string comparison.
        const FnNote* p = findNote(a, NoteKind::Pattern, "comparison");
        CHECK(p != nullptr);
        if (p) CHECK(p->va == 0);
    }

    // 5) Return value ignored (overwritten before any read).
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) { return va == 0x2000 ? std::string("foo") : std::string(); };
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 5, "mov",  "eax, 7"),
            mk(0x100A, 1, "ret",  "", true, true),
        }, o);
        const FnNote* ru = findNote(a, NoteKind::RetUse);
        CHECK(ru != nullptr);
        if (ru) CHECK(has(ru->text, "not used"));
        CHECK(a.apiCalls.size() == 1);
        if (a.apiCalls.size() == 1) {
            CHECK(a.apiCalls[0].returnValueUseKnown);
            CHECK(!a.apiCalls[0].returnValueUsed);
            CHECK(a.apiCalls[0].returnUseKind == ApiReturnUseKind::Ignored);
            CHECK(!a.apiCalls[0].resultInfluencesDecision);
        }
    }

    // 5b) Typed first-hop handling distinguishes propagation, memory storage,
    // unchanged return, and a comparison whose flags are clobbered before Jcc.
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) { return va == 0x2000 ? std::string("foo") : std::string(); };
        FuncAnnotations copied = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 3, "mov", "rbx, rax"),
            mk(0x1008, 1, "ret", "", true, true),
        }, o);
        CHECK(copied.apiCalls.size() == 1 &&
              copied.apiCalls[0].returnUseKind == ApiReturnUseKind::Propagated);

        FuncAnnotations stored = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 4, "mov", "qword ptr [rbp - 8], rax"),
            mk(0x1009, 1, "ret", "", true, true),
        }, o);
        CHECK(stored.apiCalls.size() == 1 &&
              stored.apiCalls[0].returnUseKind == ApiReturnUseKind::Stored);

        FuncAnnotations returned = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 1, "ret", "", true, true),
        }, o);
        CHECK(returned.apiCalls.size() == 1 &&
              returned.apiCalls[0].returnUseKind == ApiReturnUseKind::Returned);

        FuncAnnotations clobberedFlags = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 2, "test", "eax, eax"),
            mk(0x1007, 3, "add", "ecx, 1"),
            mk(0x100A, 2, "jne", "0x1010", true, false, 0x1010),
            mk(0x100C, 4, "mov", "eax, 1"),
            mk(0x1010, 1, "ret", "", true, true),
        }, o);
        CHECK(clobberedFlags.apiCalls.size() == 1);
        if (clobberedFlags.apiCalls.size() == 1) {
            CHECK(clobberedFlags.apiCalls[0].returnUseKind == ApiReturnUseKind::Compared);
            CHECK(!clobberedFlags.apiCalls[0].resultInfluencesDecision);
            CHECK(!clobberedFlags.apiCalls[0].decisionVAValid);
        }
    }

    // 5c) Decoder-native semantics are authoritative even when formatted
    // operand text is opaque. This is the production boundary used by both
    // Zydis and Capstone; legacy text-only instructions above remain covered.
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) {
            return va == 0x2000 || va == 0x3000
                 ? std::string("foo") : std::string();
        };

        Instruction checkedCall = mk(0x1000, 5, "call", "<opaque>",
                                     true, false, 0x2000);
        Instruction checkedTest = mk(0x1005, 2, "test", "<opaque>");
        checkedTest.typedOperands = {
            regOp("eax", OperandAccess::Read, 32),
            regOp("eax", OperandAccess::Read, 32)
        };
        checkedTest.registersRead = { "eax" };
        checkedTest.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        Instruction checkedBranch = mk(0x1007, 2, "jne", "<opaque>",
                                       false, false, 0x1010);
        checkedBranch.flow.kind = FlowKind::ConditionalBranch;
        checkedBranch.flow.directTargetValid = true;
        checkedBranch.flow.directTarget = 0x1010;
        checkedBranch.flagsRead = SemanticFlagBit(SemanticFlag::Zero);
        FuncAnnotations checked = annotate({
            checkedCall,
            checkedTest,
            checkedBranch,
            mk(0x1009, 1, "ret", "", true, true),
            mk(0x1010, 1, "ret", "", true, true),
        }, o);
        CHECK(checked.apiCalls.size() == 1);
        if (checked.apiCalls.size() == 1) {
            CHECK(checked.apiCalls[0].returnUseKind == ApiReturnUseKind::Branched);
            CHECK(checked.apiCalls[0].returnUseVAValid &&
                  checked.apiCalls[0].returnUseVA == 0x1005);
            CHECK(checked.apiCalls[0].decisionVAValid &&
                  checked.apiCalls[0].decisionVA == 0x1007);
            CHECK(checked.apiCalls[0].decisionTargetValid &&
                  checked.apiCalls[0].decisionTarget == 0x1010);
        }

        Instruction storedCall = mk(0x1100, 5, "call", "<opaque>",
                                    true, false, 0x2000);
        Instruction storedUse = mk(0x1105, 4, "mov", "<opaque>");
        storedUse.typedOperands = {
            memOp("rbp", -8, OperandAccess::Write),
            regOp("rax", OperandAccess::Read)
        };
        storedUse.registersRead = { "rbp", "rax" };
        FuncAnnotations stored = annotate({
            storedCall,
            storedUse,
            mk(0x1109, 1, "ret", "", true, true),
        }, o);
        CHECK(stored.apiCalls.size() == 1 &&
              stored.apiCalls[0].returnUseKind == ApiReturnUseKind::Stored);

        // xor eax,eax is an overwrite, not consumption of the old API result,
        // even though real decoders expose the encoded source as a register read.
        Instruction zeroCall = mk(0x1200, 5, "call", "<opaque>",
                                  true, false, 0x2000);
        Instruction zeroUse = mk(0x1205, 2, "xor", "<opaque>");
        zeroUse.typedOperands = {
            regOp("eax", OperandAccess::ReadWrite, 32),
            regOp("eax", OperandAccess::Read, 32)
        };
        zeroUse.registersRead = { "eax" };
        zeroUse.registersWritten = { "eax" };
        zeroUse.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        FuncAnnotations zeroed = annotate({
            zeroCall,
            zeroUse,
            mk(0x1207, 1, "ret", "", true, true),
        }, o);
        CHECK(zeroed.apiCalls.size() == 1 &&
              zeroed.apiCalls[0].returnUseKind == ApiReturnUseKind::Ignored);

        // A semantic call operand does not enumerate ABI clobbers. Retain the
        // explicit volatile-register model so a following call kills RAX.
        Instruction firstCall = mk(0x1300, 5, "call", "<opaque>",
                                   true, false, 0x2000);
        Instruction secondCall = mk(0x1305, 5, "call", "<opaque>",
                                    true, false, 0x3000);
        TypedOperand directTarget;
        directTarget.kind = OperandKind::Immediate;
        directTarget.access = OperandAccess::Read;
        directTarget.immediate = 0x3000;
        directTarget.pcRelative = true;
        secondCall.typedOperands.push_back(directTarget);
        FuncAnnotations clobbered = annotate({
            firstCall,
            secondCall,
            mk(0x130A, 1, "ret", "", true, true),
        }, o);
        CHECK(clobbered.apiCalls.size() == 2);
        if (clobbered.apiCalls.size() == 2) {
            CHECK(clobbered.apiCalls[0].callVA == 0x1300);
            CHECK(clobbered.apiCalls[0].returnUseKind == ApiReturnUseKind::Ignored);
        }
    }

    // 6) Loop detection + loop-phrased condition + XOR-decode pattern.
    //    for (rcx = 0; rcx < 0x10; ++rcx) buf[rcx] ^= 0x5A;
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 2, "xor", "ecx, ecx"),
            mk(0x1002, 4, "cmp", "rcx, 0x10"),
            mk(0x1006, 2, "jge", "0x1011", true, false, 0x1011),
            mk(0x1008, 4, "xor", "byte ptr [rax + rcx], 0x5A"),
            mk(0x100C, 3, "inc", "rcx"),
            mk(0x100F, 2, "jmp", "0x1002", true, false, 0x1002),
            mk(0x1011, 1, "ret", "", true, true),
        });
        CHECK(findNote(a, NoteKind::Loop, "loop start") != nullptr);
        const FnNote* p = findNote(a, NoteKind::Pattern, "XOR");
        CHECK(p != nullptr);
        if (p) {
            CHECK(p->confidence < 0.9f);          // a guess, not a fact
            CHECK(has(p->evidence, "0x1008"));    // evidence names the xor instruction
        }
        CHECK(has(a.summary, "loop"));
    }

    // 7) Loop latch describes both destinations while retaining its condition.
    //    do { --rax } while (rax != 0)
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "dec", "rax"),
            mk(0x1003, 4, "test", "rax, rax"),
            mk(0x1007, 2, "jne", "0x1000", true, false, 0x1000),
            mk(0x1009, 1, "ret", "", true, true),
        });
        const FnNote* n = findNote(a, NoteKind::Loop, "jumps to");
        if (n) CHECK(has(n->text, "otherwise falls through"));
        CHECK(n != nullptr);
        if (n) CHECK(has(n->text, "rax != 0"));
    }

    // 8) Indirect + virtual call patterns.
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "mov",  "rax, qword ptr [rcx]"),
            mk(0x1003, 3, "call", "qword ptr [rax + 0x10]", true, false, 0),
            mk(0x1006, 2, "call", "rdx", true, false, 0),
            mk(0x1008, 1, "ret",  "", true, true),
        });
        const FnNote* v = findNote(a, NoteKind::VirtualCall);
        CHECK(v != nullptr);
        if (v) {
            CHECK(has(v->text, "slot +0x10"));
            CHECK(has(v->text, "this"));          // object pointer is rcx
            CHECK(v->confidence < 0.8f);          // heuristic, not fact
        }
        CHECK(findNote(a, NoteKind::IndirectCall) != nullptr);   // call rdx
    }

    // 9) Call-argument sniffing with a string literal (x64).
    {
        AnnotateOptions o;
        o.nameFor   = [](uint64_t va) { return va == 0x2000 ? std::string("kernel32.lstrcmpA") : std::string(); };
        o.stringFor = [](uint64_t va) { return va == 0x5000 ? std::string("password") : std::string(); };
        FuncAnnotations a = annotate({
            mk(0x1000, 7, "mov",  "rcx, 0x5000"),
            mk(0x1007, 3, "mov",  "rdx, rbx"),
            mk(0x100A, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x100F, 1, "ret",  "", true, true),
        }, o);
        const FnNote* c = findNote(a, NoteKind::Call);
        CHECK(c != nullptr);
        if (c) {
            CHECK(has(c->text, "rcx=\"password\""));
            CHECK(has(c->evidence, "lstrcmpA"));
        }
        CHECK(a.apiCalls.size() == 1);
        if (a.apiCalls.size() == 1) {
            const ApiCallObservation& call = a.apiCalls.front();
            CHECK(call.callVAValid && call.callVA == 0x100A);
            CHECK(call.targetVAValid && call.targetVA == 0x2000);
            CHECK(has(call.resolvedName, "lstrcmpA"));
            CHECK(call.arguments.size() == 2);
            if (!call.arguments.empty()) {
                CHECK(call.arguments[0].index == 0);
                CHECK(call.arguments[0].abiLocation == "rcx");
                CHECK(call.arguments[0].referencedAddressValid);
                CHECK(call.arguments[0].referencedAddress == 0x5000);
                CHECK(call.arguments[0].stringLiteral == "password");
                CHECK(!call.arguments[0].evidence.empty());
            }
        }
    }

    // 10) x86 push-argument sniffing.
    {
        AnnotateOptions o; o.x64 = false;
        o.nameFor   = [](uint64_t va) { return va == 0x2000 ? std::string("msvcrt.printf") : std::string(); };
        o.stringFor = [](uint64_t va) { return va == 0x5000 ? std::string("hello %s") : std::string(); };
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "push", "0x5000"),
            mk(0x1005, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x100A, 3, "add",  "esp, 4"),
            mk(0x100D, 1, "ret",  "", true, true),
        }, o);
        const FnNote* c = findNote(a, NoteKind::Call);
        CHECK(c != nullptr);
        if (c) CHECK(has(c->text, "arg1=\"hello %s\""));
    }

    // 10b) The bounded Windows API database names recovered parameters and
    // renders well-known bitmasks symbolically; provenance stays explicit.
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) {
            return va == 0x2000 ? std::string("kernel32.VirtualAlloc") : std::string();
        };
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "xor",  "rcx, rcx"),
            mk(0x1003, 7, "mov",  "rdx, 0x1000"),
            mk(0x100A, 6, "mov",  "r8, 0x3000"),
            mk(0x1010, 6, "mov",  "r9, 0x40"),
            mk(0x1016, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x101B, 1, "ret",  "", true, true),
        }, o);
        const FnNote* c = findNote(a, NoteKind::Call);
        CHECK(c != nullptr);
        if (c) {
            CHECK(has(c->text, "address=0"));
            CHECK(has(c->text, "size=0x1000"));
            CHECK(has(c->text, "allocationType=MEM_COMMIT | MEM_RESERVE"));
            CHECK(has(c->text, "protection=PAGE_EXECUTE_READWRITE"));
            CHECK(has(c->evidence, "bounded Windows API database"));
        }
        CHECK(a.apiCalls.size() == 1);
        if (a.apiCalls.size() == 1) {
            CHECK(a.apiCalls[0].arguments.size() == 4);
            if (a.apiCalls[0].arguments.size() == 4) {
                CHECK(a.apiCalls[0].arguments[1].parameter == "size");
                CHECK(a.apiCalls[0].arguments[1].immediateValid);
                CHECK(a.apiCalls[0].arguments[1].immediate == 0x1000);
                CHECK(a.apiCalls[0].arguments[3].parameter == "protection");
            }
        }
    }

    // 10c) Exact network prototypes expose request-header and URL literals as
    // typed observations, rather than forcing downstream triage to parse note
    // prose or guess register meanings.
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) {
            return va == 0x2000
                ? std::string("winhttp.WinHttpAddRequestHeadersW")
                : std::string();
        };
        o.stringFor = [](uint64_t va) {
            return va == 0x5000
                ? std::string("Authorization: Bearer crackme-token")
                : std::string();
        };
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "mov", "rcx, rbx"),
            mk(0x1003, 7, "mov", "rdx, 0x5000"),
            mk(0x100A, 6, "mov", "r8, 0xFFFFFFFF"),
            mk(0x1010, 6, "mov", "r9, 0x20000000"),
            mk(0x1016, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x101B, 1, "ret", "", true, true),
        }, o);
        CHECK(a.apiCalls.size() == 1);
        if (a.apiCalls.size() == 1) {
            const ApiCallObservation& call = a.apiCalls.front();
            CHECK(call.arguments.size() == 4);
            if (call.arguments.size() == 4) {
                CHECK(call.arguments[1].parameter == "headers");
                CHECK(call.arguments[1].referencedAddressValid);
                CHECK(call.arguments[1].referencedAddress == 0x5000);
                CHECK(call.arguments[1].stringLiteral ==
                      "Authorization: Bearer crackme-token");
                CHECK(call.arguments[2].parameter == "headersLength");
                CHECK(call.arguments[3].parameter == "modifiers");
            }
        }
    }
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) {
            return va == 0x2000 ? std::string("winhttp.WinHttpConnect")
                                : std::string();
        };
        o.stringFor = [](uint64_t va) {
            return va == 0x7000 ? std::string("port.example.net")
                                : std::string();
        };
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "mov", "rcx, rbx"),
            mk(0x1003, 7, "mov", "rdx, 0x7000"),
            mk(0x100A, 6, "mov", "r8, 0x20FB"), // 8443
            mk(0x1010, 3, "xor", "r9, r9"),
            mk(0x1013, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1018, 1, "ret", "", true, true),
        }, o);
        CHECK(a.apiCalls.size() == 1);
        if (a.apiCalls.size() == 1 && a.apiCalls[0].arguments.size() == 4) {
            const ApiCallObservation& call = a.apiCalls[0];
            CHECK(call.arguments[1].parameter == "serverName");
            CHECK(call.arguments[1].stringLiteral == "port.example.net");
            CHECK(call.arguments[2].parameter == "serverPort");
            CHECK(call.arguments[2].immediateValid);
            CHECK(call.arguments[2].immediate == 8443);
        }
    }
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) {
            return va == 0x2000 ? std::string("wininet.InternetOpenUrlW")
                                : std::string();
        };
        o.stringFor = [](uint64_t va) {
            return va == 0x6000
                ? std::string("https://typed.example.net/activate")
                : std::string();
        };
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "mov", "rcx, rbx"),
            mk(0x1003, 7, "mov", "rdx, 0x6000"),
            mk(0x100A, 3, "xor", "r8, r8"),
            mk(0x100D, 3, "xor", "r9, r9"),
            mk(0x1010, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1015, 1, "ret", "", true, true),
        }, o);
        CHECK(a.apiCalls.size() == 1);
        if (a.apiCalls.size() == 1 && a.apiCalls[0].arguments.size() >= 2) {
            CHECK(a.apiCalls[0].arguments[1].parameter == "url");
            CHECK(a.apiCalls[0].arguments[1].stringLiteral ==
                  "https://typed.example.net/activate");
        }
    }
    {
        // Microsoft x64 argument five and later live in stack slots following
        // the 32-byte shadow space. Persistent-state APIs rely on these output
        // and data parameters, so they must remain typed observations too.
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) {
            return va == 0x2000 ? std::string("advapi32!RegSetValueExW")
                                : std::string();
        };
        o.stringFor = [](uint64_t va) {
            return va == 0x5000 ? std::string("remembered-license")
                                : std::string();
        };
        FuncAnnotations a = annotate({
            mk(0x1000, 3, "mov", "rcx, rbx"),
            mk(0x1003, 7, "mov", "rdx, 0x6000"),
            mk(0x100A, 3, "xor", "r8, r8"),
            mk(0x100D, 6, "mov", "r9d, 1"),
            mk(0x1013, 9, "mov", "qword ptr [rsp + 0x20], 0x5000"),
            mk(0x101C, 9, "mov", "qword ptr [rsp + 0x28], 0x10"),
            mk(0x1025, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x102A, 1, "ret", "", true, true),
        }, o);
        CHECK(a.apiCalls.size() == 1);
        if (a.apiCalls.size() == 1) {
            const ApiCallObservation& call = a.apiCalls.front();
            CHECK(call.arguments.size() == 6);
            if (call.arguments.size() == 6) {
                CHECK(call.arguments[4].index == 4);
                CHECK(call.arguments[4].abiLocation == "[rsp+0x20]");
                CHECK(call.arguments[4].parameter == "data");
                CHECK(call.arguments[4].referencedAddressValid);
                CHECK(call.arguments[4].referencedAddress == 0x5000);
                CHECK(call.arguments[4].stringLiteral == "remembered-license");
                CHECK(call.arguments[5].index == 5);
                CHECK(call.arguments[5].abiLocation == "[rsp+0x28]");
                CHECK(call.arguments[5].parameter == "dataSize");
                CHECK(call.arguments[5].immediateValid);
                CHECK(call.arguments[5].immediate == 0x10);
            }
        }
    }

    // 11) Vtable pointer store (lea code-pointer + store to [obj+0]).
    {
        AnnotateOptions o;
        o.looksLikeVtable = [](uint64_t va) { return va == 0x3000; };
        FuncAnnotations a = annotate({
            mk(0x1000, 7, "lea", "rax, [rip + 0x1FF9]"),    // -> 0x1000+7+0x1FF9 = 0x3000
            mk(0x1007, 3, "mov", "qword ptr [rcx], rax"),
            mk(0x100A, 1, "ret", "", true, true),
        }, o);
        const FnNote* v = findNote(a, NoteKind::Vtable);
        CHECK(v != nullptr);
        if (v) {
            CHECK(has(v->text, "0x3000"));
            CHECK(has(v->text, "construction"));
        }
    }

    // 12) Switch dispatch (hand-built CFG, since the mock has no jump-table memory).
    {
        ControlFlowGraph g; g.funcStart = 0x1000;
        BasicBlock b; b.start = 0x1000; b.end = 0x1007;
        b.insns = { mk(0x1000, 7, "jmp", "qword ptr [rax*8 + 0x4000]", true, false, 0) };
        b.isSwitch = true; b.caseTargets = { 0x1100, 0x1200, 0x1300 };
        g.blocks.push_back(b);
        FuncAnnotations a = AnnotateFunction(g, {});
        const FnNote* n = findNote(a, NoteKind::Switch);
        CHECK(n != nullptr);
        if (n) CHECK(has(n->text, "3 case(s)"));
    }

    // 13) Register lifetimes: rbx written then read later.
    {
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "mov", "rbx, 0x1234"),
            mk(0x1005, 3, "mov", "rax, rbx"),
            mk(0x1008, 1, "ret", "", true, true),
        });
        bool foundRbx = false;
        for (const RegLifetime& r : a.regs)
            if (r.reg == "rbx") { foundRbx = true; CHECK(r.firstVA == 0x1000); CHECK(r.lastVA == 0x1005); CHECK(r.writes == 1); CHECK(r.reads == 1); }
        CHECK(foundRbx);
    }

    // 14) Function-level API patterns: input reading + timers.
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) -> std::string {
            if (va == 0x2000) return "kernel32.ReadConsoleA";
            if (va == 0x2100) return "kernel32.GetTickCount";
            return {};
        };
        FuncAnnotations a = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 5, "call", "0x2100", true, false, 0x2100),
            mk(0x100A, 1, "ret",  "", true, true),
        }, o);
        CHECK(findNote(a, NoteKind::Pattern, "user input") != nullptr);
        CHECK(findNote(a, NoteKind::Pattern, "timer") != nullptr);
    }

    // 15) ApiPurpose (moved to Core/ApiInfo.h) sanity.
    CHECK(has(ApiPurpose("kernel32.CreateFileW"), "file"));
    CHECK(has(ApiPurpose("msvcrt.strcmp"), "compare"));
    CHECK(has(ApiPurpose("ws2_32.dll.send"), "network"));
    CHECK(ApiPurpose("user32.dll.SendMessageW").empty());
    CHECK(ApiPurpose("kernel32.dll.ConnectNamedPipeW").empty());
    CHECK(ApiPurpose("totally_unknown_api").empty());

    // 16) Network pattern matching is exact and DLL-aware. A user-interface
    // SendMessageW call must not be mistaken for Winsock send().
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) {
            if (va == 0x2000) return std::string("user32.dll.SendMessageW");
            if (va == 0x2100) return std::string("kernel32.dll.ConnectNamedPipeW");
            if (va == 0x3000) return std::string("ws2_32.dll.send");
            return std::string();
        };
        FuncAnnotations uiOnly = annotate({
            mk(0x1000, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1005, 5, "call", "0x2100", true, false, 0x2100),
            mk(0x100A, 1, "ret", "", true, true),
        }, o);
        CHECK(findNote(uiOnly, NoteKind::Pattern, "network I/O") == nullptr);
        CHECK(findNote(uiOnly, NoteKind::Call, "network") == nullptr);

        FuncAnnotations socketCall = annotate({
            mk(0x1000, 5, "call", "0x3000", true, false, 0x3000),
            mk(0x1005, 1, "ret", "", true, true),
        }, o);
        const FnNote* network = findNote(socketCall, NoteKind::Pattern, "network I/O");
        CHECK(network != nullptr);
        if (network) CHECK(has(network->evidence, "ws2_32!send"));
    }

    // 17) A receive API's BOOL is only transport status.  The useful crackme
    // lead is the later comparison that consumes the cataloged reply buffer,
    // including the match/mismatch branch reached after the status split.
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) {
            if (va == 0x2000) return std::string("winhttp!WinHttpReadData");
            if (va == 0x3000) return std::string("msvcrt!strcmp");
            return std::string();
        };
        o.stringFor = [](uint64_t va) {
            return va == 0x5000 ? std::string("MAGIC42") : std::string();
        };
        FuncAnnotations a = annotate({
            mk(0x1000, 4, "lea",  "rdx, [rbp - 0x80]"),
            mk(0x1004, 3, "mov",  "rcx, rbx"),
            mk(0x1007, 6, "mov",  "r8d, 0x40"),
            mk(0x100D, 4, "lea",  "r9, [rbp - 0x88]"),
            mk(0x1011, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1016, 2, "test", "eax, eax"),
            mk(0x1018, 2, "je",   "0x1034", true, false, 0x1034),
            mk(0x101A, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x101E, 7, "mov",  "rdx, 0x5000"),
            mk(0x1025, 5, "call", "0x3000", true, false, 0x3000),
            mk(0x102A, 2, "test", "eax, eax"),
            mk(0x102C, 2, "jne",  "0x1034", true, false, 0x1034),
            mk(0x102E, 5, "mov",  "eax, 1"),
            mk(0x1033, 1, "ret",  "", true, true),
            mk(0x1034, 2, "xor",  "eax, eax"),
            mk(0x1036, 1, "ret",  "", true, true),
        }, o);
        CHECK(a.apiCalls.size() == 2);
        if (a.apiCalls.size() == 2) {
            const ApiCallObservation& read = a.apiCalls[0];
            CHECK(read.replyDecisionAnalysisAttempted);
            CHECK(read.replyDecisionsComplete);
            CHECK(read.replyDecisions.size() == 1);
            if (read.replyDecisions.size() == 1) {
                const ApiReplyDecisionObservation& decision =
                    read.replyDecisions.front();
                CHECK(decision.kind == ApiReplyDecisionKind::ComparisonCall);
                CHECK(decision.outputArgumentIndex == 1);
                CHECK(has(decision.outputRole, "payload"));
                CHECK(decision.comparisonVAValid &&
                      decision.comparisonVA == 0x1025);
                CHECK(decision.decisionVAValid &&
                      decision.decisionVA == 0x102C);
                CHECK(has(decision.expectedValue, "MAGIC42"));
                CHECK(decision.matchVAValid && decision.matchVA == 0x102E);
                CHECK(decision.mismatchVAValid && decision.mismatchVA == 0x1034);
                CHECK(has(decision.takenPathSummary, "differs"));
                CHECK(has(decision.fallthroughPathSummary, "matches"));
                CHECK(!decision.evidence.empty());
            }
        }

        FuncAnnotations statusOnly = annotate({
            mk(0x1100, 4, "lea",  "rdx, [rbp - 0x80]"),
            mk(0x1104, 3, "mov",  "rcx, rbx"),
            mk(0x1107, 6, "mov",  "r8d, 0x40"),
            mk(0x110D, 4, "lea",  "r9, [rbp - 0x88]"),
            mk(0x1111, 5, "call", "0x2000", true, false, 0x2000),
            mk(0x1116, 2, "test", "eax, eax"),
            mk(0x1118, 2, "je",   "0x111B", true, false, 0x111B),
            mk(0x111A, 1, "ret",  "", true, true),
            mk(0x111B, 1, "ret",  "", true, true),
        }, o);
        CHECK(statusOnly.apiCalls.size() == 1);
        if (statusOnly.apiCalls.size() == 1) {
            CHECK(statusOnly.apiCalls[0].resultInfluencesDecision);
            CHECK(statusOnly.apiCalls[0].replyDecisionAnalysisAttempted);
            CHECK(statusOnly.apiCalls[0].replyDecisions.empty());
        }
    }

    // 18) Fixed-output local input flows retain exact buffer provenance through
    // an exact cataloged comparator and expose the match/mismatch branch. Nearby
    // stack buffers, missing origins, zero-length comparisons, and format-driven
    // scanf outputs must never be promoted to the same observation.
    {
        AnnotateOptions o;
        o.nameFor = [](uint64_t va) {
            if (va == 0x8000) return std::string("user32!GetDlgItemTextA");
            if (va == 0x8100) return std::string("msvcrt!strcmp");
            if (va == 0x8200) return std::string("ucrtbase!fgets");
            if (va == 0x8300) return std::string("ucrtbase!scanf");
            if (va == 0x8400) return std::string("msvcrt!strncmp");
            if (va == 0x8600) return std::string("msvcrt!memcmp");
            return std::string();
        };
        o.stringFor = [](uint64_t va) {
            if (va == 0x9000) return std::string("SERIAL-123");
            if (va == 0x9100) return std::string("%31s");
            if (va == 0x9200)
                return std::string("0123456789012345678901234567890123456789TAIL");
            if (va == 0x9300) return std::string("OPEN");
            if (va == 0x9400) return std::string("OK");
            return std::string();
        };

        FuncAnnotations dialog = annotate({
            mk(0x4000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0x4004, 5, "mov",  "edx, 0x65"),
            mk(0x4009, 3, "mov",  "rcx, rbx"),
            mk(0x400C, 6, "mov",  "r9d, 0x40"),
            mk(0x4012, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x4017, 7, "mov",  "rdx, 0x9000"),
            mk(0x401E, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x4022, 5, "call", "0x8100", true, false, 0x8100),
            mk(0x4027, 2, "test", "eax, eax"),
            mk(0x4029, 2, "je",   "0x4030", true, false, 0x4030),
            mk(0x402B, 2, "xor",  "eax, eax"),
            mk(0x402D, 1, "ret",  "", true, true),
            mk(0x4030, 5, "mov",  "eax, 1"),
            mk(0x4035, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* dialogInput = findCall(dialog, 0x4012);
        CHECK(dialogInput != nullptr);
        if (dialogInput) {
            CHECK(dialogInput->localInputDecisionAnalysisAttempted);
            CHECK(dialogInput->localInputDecisionsComplete);
            CHECK(dialogInput->localInputDecisionIncompleteReason.empty());
            CHECK(dialogInput->localInputDecisions.size() == 1);
            if (dialogInput->localInputDecisions.size() == 1) {
                const ApiLocalInputDecisionObservation& decision =
                    dialogInput->localInputDecisions.front();
                CHECK(decision.kind == ApiLocalInputDecisionKind::ComparisonCall);
                CHECK(decision.outputArgumentIndex == 2);
                CHECK(decision.inputEncoding == "narrow text");
                CHECK(decision.comparatorName == "msvcrt!strcmp");
                CHECK(decision.comparatorCallVAValid &&
                      decision.comparatorCallVA == 0x4022);
                CHECK(decision.comparisonVAValid && decision.comparisonVA == 0x4022);
                CHECK(decision.decisionVAValid && decision.decisionVA == 0x4029);
                CHECK(decision.decisionTargetValid && decision.decisionTarget == 0x4030);
                CHECK(decision.fallthroughVAValid && decision.fallthroughVA == 0x402B);
                CHECK(decision.expectedValue == "\"SERIAL-123\"");
                CHECK(decision.matchVAValid && decision.matchVA == 0x4030);
                CHECK(decision.mismatchVAValid && decision.mismatchVA == 0x402B);
                CHECK(has(decision.takenPathSummary, "matches"));
                CHECK(has(decision.fallthroughPathSummary, "differs"));
                CHECK(has(decision.evidence, "exact recovered output origin"));
                CHECK(has(decision.evidence, "does not prove"));
                CHECK(decision.confidence > 0.0f && decision.confidence < 1.0f);
            }
        }

        // jne reverses the path labels: its target is mismatch and its
        // fallthrough is match for a strcmp-style zero-is-equal result.
        FuncAnnotations line = annotate({
            mk(0x5000, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x5004, 5, "mov",  "edx, 0x40"),
            mk(0x5009, 3, "mov",  "r8, rbx"),
            mk(0x500C, 5, "call", "0x8200", true, false, 0x8200),
            mk(0x5011, 7, "mov",  "rdx, 0x9000"),
            mk(0x5018, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x501C, 5, "call", "0x8100", true, false, 0x8100),
            mk(0x5021, 2, "test", "eax, eax"),
            mk(0x5023, 2, "jne",  "0x5030", true, false, 0x5030),
            mk(0x5025, 5, "mov",  "eax, 1"),
            mk(0x502A, 1, "ret",  "", true, true),
            mk(0x5030, 2, "xor",  "eax, eax"),
            mk(0x5032, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* lineInput = findCall(line, 0x500C);
        CHECK(lineInput != nullptr);
        if (lineInput) {
            CHECK(lineInput->localInputDecisionAnalysisAttempted);
            CHECK(lineInput->localInputDecisionsComplete);
            CHECK(lineInput->localInputDecisions.size() == 1);
            if (lineInput->localInputDecisions.size() == 1) {
                const ApiLocalInputDecisionObservation& decision =
                    lineInput->localInputDecisions.front();
                CHECK(decision.outputArgumentIndex == 0);
                CHECK(decision.decisionVAValid && decision.decisionVA == 0x5023);
                CHECK(decision.matchVAValid && decision.matchVA == 0x5025);
                CHECK(decision.mismatchVAValid && decision.mismatchVA == 0x5030);
                CHECK(has(decision.takenPathSummary, "differs"));
                CHECK(has(decision.fallthroughPathSummary, "matches"));
            }
        }

        // The reply analysis intentionally permits offsets inside a bounded
        // response window. Local input must be stricter: this nearby local is
        // a different buffer and cannot satisfy the comparator contract.
        FuncAnnotations unrelated = annotate({
            mk(0x6000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0x6004, 5, "mov",  "edx, 0x65"),
            mk(0x6009, 3, "mov",  "rcx, rbx"),
            mk(0x600C, 6, "mov",  "r9d, 0x40"),
            mk(0x6012, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x6017, 7, "mov",  "rdx, 0x9000"),
            mk(0x601E, 4, "lea",  "rcx, [rbp - 0x40]"),
            mk(0x6022, 5, "call", "0x8100", true, false, 0x8100),
            mk(0x6027, 2, "test", "eax, eax"),
            mk(0x6029, 2, "je",   "0x6030", true, false, 0x6030),
            mk(0x602B, 1, "ret",  "", true, true),
            mk(0x6030, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* unrelatedInput = findCall(unrelated, 0x6012);
        CHECK(unrelatedInput != nullptr);
        if (unrelatedInput) {
            CHECK(unrelatedInput->localInputDecisionAnalysisAttempted);
            CHECK(unrelatedInput->localInputDecisionsComplete);
            CHECK(unrelatedInput->localInputDecisions.empty());
        }

        FuncAnnotations unknownOrigin = annotate({
            mk(0x7000, 3, "mov",  "r8, rbx"),
            mk(0x7003, 5, "mov",  "edx, 0x65"),
            mk(0x7008, 3, "mov",  "rcx, rdi"),
            mk(0x700B, 6, "mov",  "r9d, 0x40"),
            mk(0x7011, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x7016, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* unknownInput = findCall(unknownOrigin, 0x7011);
        CHECK(unknownInput != nullptr);
        if (unknownInput) {
            CHECK(unknownInput->localInputDecisionAnalysisAttempted);
            CHECK(!unknownInput->localInputDecisionsComplete);
            CHECK(unknownInput->localInputDecisions.empty());
            CHECK(has(unknownInput->localInputDecisionIncompleteReason, "origin"));
        }

        FuncAnnotations scanfInput = annotate({
            mk(0x7100, 7, "mov",  "rcx, 0x9100"),
            mk(0x7107, 4, "lea",  "rdx, [rbp - 0x80]"),
            mk(0x710B, 5, "call", "0x8300", true, false, 0x8300),
            mk(0x7110, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* scanfCall = findCall(scanfInput, 0x710B);
        CHECK(scanfCall != nullptr);
        if (scanfCall) {
            CHECK(!scanfCall->localInputDecisionAnalysisAttempted);
            CHECK(scanfCall->localInputDecisionsComplete);
            CHECK(scanfCall->localInputDecisions.empty());
        }

        // strncmp(..., 0) is equal without examining either buffer. Even with
        // an expected literal and an adjacent branch it is not a data-flow gate.
        FuncAnnotations zeroLength = annotate({
            mk(0x7200, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0x7204, 5, "mov",  "edx, 0x65"),
            mk(0x7209, 3, "mov",  "rcx, rbx"),
            mk(0x720C, 6, "mov",  "r9d, 0x40"),
            mk(0x7212, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x7217, 7, "mov",  "rdx, 0x9000"),
            mk(0x721E, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x7222, 3, "xor",  "r8d, r8d"),
            mk(0x7225, 5, "call", "0x8400", true, false, 0x8400),
            mk(0x722A, 2, "test", "eax, eax"),
            mk(0x722C, 2, "je",   "0x7230", true, false, 0x7230),
            mk(0x722E, 1, "ret",  "", true, true),
            mk(0x7230, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* zeroLengthInput = findCall(zeroLength, 0x7212);
        CHECK(zeroLengthInput != nullptr);
        if (zeroLengthInput) {
            CHECK(zeroLengthInput->localInputDecisionAnalysisAttempted);
            CHECK(zeroLengthInput->localInputDecisionsComplete);
            CHECK(zeroLengthInput->localInputDecisions.empty());
        }

        // x86 reverse-push recovery uses the same catalog argument ordinals.
        // In particular, GetDlgItemTextA's third argument is the output buffer.
        AnnotateOptions x86 = o;
        x86.x64 = false;
        FuncAnnotations x86Dialog = annotate({
            mk(0x7300, 2, "push", "0x40"),
            mk(0x7302, 3, "lea",  "eax, [ebp - 0x80]"),
            mk(0x7305, 1, "push", "eax"),
            mk(0x7306, 2, "push", "0x65"),
            mk(0x7308, 1, "push", "ebx"),
            mk(0x7309, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x730E, 5, "push", "0x9000"),
            mk(0x7313, 3, "lea",  "eax, [ebp - 0x80]"),
            mk(0x7316, 1, "push", "eax"),
            mk(0x7317, 5, "call", "0x8100", true, false, 0x8100),
            mk(0x731C, 2, "test", "eax, eax"),
            mk(0x731E, 2, "je",   "0x7328", true, false, 0x7328),
            mk(0x7320, 1, "ret",  "", true, true),
            mk(0x7328, 1, "ret",  "", true, true),
        }, x86);
        const ApiCallObservation* x86Input = findCall(x86Dialog, 0x7309);
        CHECK(x86Input != nullptr);
        if (x86Input) {
            CHECK(x86Input->localInputDecisionAnalysisAttempted);
            CHECK(x86Input->localInputDecisionsComplete);
            CHECK(x86Input->localInputDecisions.size() == 1);
            if (x86Input->localInputDecisions.size() == 1) {
                const ApiLocalInputDecisionObservation& decision =
                    x86Input->localInputDecisions.front();
                CHECK(decision.outputArgumentIndex == 2);
                CHECK(decision.matchVAValid && decision.matchVA == 0x7328);
                CHECK(decision.mismatchVAValid && decision.mismatchVA == 0x7320);
            }
        }

        // A direct x86 push must retain immediate validity so a positive
        // strncmp bound can prove that the comparator actually reads data.
        FuncAnnotations x86Bounded = annotate({
            mk(0x7400, 2, "push", "0x40"),
            mk(0x7402, 3, "lea",  "eax, [ebp - 0x80]"),
            mk(0x7405, 1, "push", "eax"),
            mk(0x7406, 2, "push", "0x65"),
            mk(0x7408, 1, "push", "ebx"),
            mk(0x7409, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x740E, 2, "push", "0x0A"),
            mk(0x7410, 5, "push", "0x9000"),
            mk(0x7415, 3, "lea",  "eax, [ebp - 0x80]"),
            mk(0x7418, 1, "push", "eax"),
            mk(0x7419, 5, "call", "0x8400", true, false, 0x8400),
            mk(0x741E, 2, "test", "eax, eax"),
            mk(0x7420, 2, "jne",  "0x7428", true, false, 0x7428),
            mk(0x7422, 1, "ret",  "", true, true),
            mk(0x7428, 1, "ret",  "", true, true),
        }, x86);
        const ApiCallObservation* x86Strncmp = findCall(x86Bounded, 0x7419);
        CHECK(x86Strncmp != nullptr);
        if (x86Strncmp) {
            bool foundLength = false;
            for (const ApiArgumentObservation& argument : x86Strncmp->arguments) {
                if (argument.index == 2) {
                    foundLength = true;
                    CHECK(argument.immediateValid);
                    CHECK(argument.immediate == 10);
                }
            }
            CHECK(foundLength);
        }
        const ApiCallObservation* x86BoundedInput = findCall(x86Bounded, 0x7409);
        CHECK(x86BoundedInput != nullptr);
        if (x86BoundedInput) {
            CHECK(x86BoundedInput->localInputDecisionsComplete);
            CHECK(x86BoundedInput->localInputDecisions.size() == 1);
            if (x86BoundedInput->localInputDecisions.size() == 1)
                CHECK(has(x86BoundedInput->localInputDecisions.front().evidence,
                          "exact recovered nonzero comparison length"));
        }

        // fgets documents that its successful return aliases argument one.
        // Preserve that lineage through registers, but only within the bounded
        // same-block proof used by the local decision pass.
        FuncAnnotations returnedBuffer = annotate({
            mk(0x7500, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x7504, 5, "mov",  "edx, 0x40"),
            mk(0x7509, 3, "mov",  "r8, rbx"),
            mk(0x750C, 5, "call", "0x8200", true, false, 0x8200),
            mk(0x7511, 3, "mov",  "rcx, rax"),
            mk(0x7514, 7, "mov",  "rdx, 0x9000"),
            mk(0x751B, 5, "call", "0x8100", true, false, 0x8100),
            mk(0x7520, 2, "test", "eax, eax"),
            mk(0x7522, 2, "je",   "0x7528", true, false, 0x7528),
            mk(0x7524, 1, "ret",  "", true, true),
            mk(0x7528, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* returnedInput = findCall(returnedBuffer, 0x750C);
        CHECK(returnedInput != nullptr);
        if (returnedInput) {
            CHECK(returnedInput->localInputDecisionsComplete);
            CHECK(returnedInput->localInputDecisions.size() == 1);
            if (returnedInput->localInputDecisions.size() == 1)
                CHECK(has(returnedInput->localInputDecisions.front().evidence,
                          "producer return aliases its output"));
        }

        // Resolver strings are bounded previews. A value longer than the cap
        // must remain visibly a prefix rather than masquerading as the exact
        // secret consumed by strcmp.
        FuncAnnotations longLiteral = annotate({
            mk(0x7600, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0x7604, 5, "mov",  "edx, 0x65"),
            mk(0x7609, 3, "mov",  "rcx, rbx"),
            mk(0x760C, 6, "mov",  "r9d, 0x40"),
            mk(0x7612, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x7617, 7, "mov",  "rdx, 0x9200"),
            mk(0x761E, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x7622, 5, "call", "0x8100", true, false, 0x8100),
            mk(0x7627, 2, "test", "eax, eax"),
            mk(0x7629, 2, "je",   "0x7630", true, false, 0x7630),
            mk(0x762B, 1, "ret",  "", true, true),
            mk(0x7630, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* longCompare = findCall(longLiteral, 0x7622);
        CHECK(longCompare != nullptr);
        if (longCompare) {
            bool sawTruncatedLiteral = false;
            for (const ApiArgumentObservation& argument : longCompare->arguments) {
                if (argument.index == 1) {
                    sawTruncatedLiteral = true;
                    CHECK(argument.stringLiteral.size() == 40);
                    CHECK(argument.stringLiteralTruncated);
                }
            }
            CHECK(sawTruncatedLiteral);
        }
        const ApiCallObservation* longInput = findCall(longLiteral, 0x7612);
        CHECK(longInput != nullptr);
        if (longInput && longInput->localInputDecisions.size() == 1) {
            const ApiLocalInputDecisionObservation& decision =
                longInput->localInputDecisions.front();
            CHECK(has(decision.expectedValue, "..."));
            CHECK(has(decision.expectedValue, "truncated resolver prefix"));
            CHECK(!has(decision.expectedValue, "TAIL"));
            CHECK(has(decision.evidence, "40-byte preview cap"));
        } else {
            CHECK(false);
        }

        // A later exact producer to the same local supersedes the earlier
        // origin. Only the fresh producer may own the subsequent strcmp gate.
        FuncAnnotations replaced = annotate({
            mk(0xB000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0xB004, 5, "mov",  "edx, 0x65"),
            mk(0xB009, 3, "mov",  "rcx, rbx"),
            mk(0xB00C, 6, "mov",  "r9d, 0x40"),
            mk(0xB012, 5, "call", "0x8000", true, false, 0x8000),
            mk(0xB017, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0xB01B, 5, "mov",  "edx, 0x66"),
            mk(0xB020, 3, "mov",  "rcx, rbx"),
            mk(0xB023, 6, "mov",  "r9d, 0x40"),
            mk(0xB029, 5, "call", "0x8000", true, false, 0x8000),
            mk(0xB02E, 7, "mov",  "rdx, 0x9000"),
            mk(0xB035, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0xB039, 5, "call", "0x8100", true, false, 0x8100),
            mk(0xB03E, 2, "test", "eax, eax"),
            mk(0xB040, 2, "je",   "0xB048", true, false, 0xB048),
            mk(0xB042, 1, "ret",  "", true, true),
            mk(0xB048, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* staleInput = findCall(replaced, 0xB012);
        const ApiCallObservation* freshInput = findCall(replaced, 0xB029);
        CHECK(staleInput != nullptr);
        CHECK(freshInput != nullptr);
        if (staleInput) {
            CHECK(staleInput->localInputDecisionAnalysisAttempted);
            CHECK(!staleInput->localInputDecisionsComplete);
            CHECK(staleInput->localInputDecisions.empty());
            CHECK(has(staleInput->localInputDecisionIncompleteReason,
                      "later exact fixed-output producer"));
            CHECK(has(staleInput->localInputDecisionIncompleteReason,
                      "stale attribution"));
        }
        if (freshInput) {
            CHECK(freshInput->localInputDecisionAnalysisAttempted);
            CHECK(freshInput->localInputDecisionsComplete);
            CHECK(freshInput->localInputDecisions.size() == 1);
        }

        // A direct write to the exact local between input and comparison breaks
        // content provenance even though the pointer expression is unchanged.
        FuncAnnotations overwritten = annotate({
            mk(0xC000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0xC004, 5, "mov",  "edx, 0x65"),
            mk(0xC009, 3, "mov",  "rcx, rbx"),
            mk(0xC00C, 6, "mov",  "r9d, 0x40"),
            mk(0xC012, 5, "call", "0x8000", true, false, 0x8000),
            mk(0xC017, 4, "mov",  "byte ptr [rbp - 0x80], 0"),
            mk(0xC01B, 7, "mov",  "rdx, 0x9000"),
            mk(0xC022, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0xC026, 5, "call", "0x8100", true, false, 0x8100),
            mk(0xC02B, 2, "test", "eax, eax"),
            mk(0xC02D, 2, "je",   "0xC034", true, false, 0xC034),
            mk(0xC02F, 1, "ret",  "", true, true),
            mk(0xC034, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* overwrittenInput = findCall(overwritten, 0xC012);
        CHECK(overwrittenInput != nullptr);
        if (overwrittenInput) {
            CHECK(!overwrittenInput->localInputDecisionsComplete);
            CHECK(overwrittenInput->localInputDecisions.empty());
            CHECK(has(overwrittenInput->localInputDecisionIncompleteReason,
                      "intervening write"));
        }

        // Hostile functions cannot trigger unbounded producer work. Producers
        // past the deterministic cap stay typed but explicitly incomplete.
        std::vector<Instruction> cappedProducerCode;
        std::vector<uint64_t> cappedProducerCalls;
        uint64_t cursor = 0xD000;
        for (size_t producerNumber = 0; producerNumber < 17; ++producerNumber) {
            cappedProducerCode.push_back(
                mk(cursor, 4, "lea", "r8, [rbp - 0x80]"));
            cursor += 4;
            cappedProducerCode.push_back(mk(cursor, 5, "mov", "edx, 0x65"));
            cursor += 5;
            cappedProducerCode.push_back(mk(cursor, 3, "mov", "rcx, rbx"));
            cursor += 3;
            cappedProducerCode.push_back(mk(cursor, 6, "mov", "r9d, 0x40"));
            cursor += 6;
            cappedProducerCalls.push_back(cursor);
            cappedProducerCode.push_back(
                mk(cursor, 5, "call", "0x8000", true, false, 0x8000));
            cursor += 5;
        }
        cappedProducerCode.push_back(mk(cursor, 1, "ret", "", true, true));
        FuncAnnotations cappedProducers = annotate(cappedProducerCode, o);
        CHECK(cappedProducerCalls.size() == 17);
        const ApiCallObservation* cappedInput =
            findCall(cappedProducers, cappedProducerCalls.back());
        CHECK(cappedInput != nullptr);
        if (cappedInput) {
            CHECK(cappedInput->localInputDecisionAnalysisAttempted);
            CHECK(!cappedInput->localInputDecisionsComplete);
            CHECK(cappedInput->localInputDecisions.empty());
            CHECK(has(cappedInput->localInputDecisionIncompleteReason,
                      "producer cap"));
        }

        // If every eligible producer falls after the named-call classification
        // cap, the function-level completeness bit still discloses that local
        // decisions may have been omitted.
        std::vector<Instruction> cappedCallCode;
        cursor = 0xE000;
        for (size_t callNumber = 0; callNumber < 256; ++callNumber) {
            cappedCallCode.push_back(
                mk(cursor, 5, "call", "0x8500", true, false, 0x8500));
            cursor += 5;
        }
        cappedCallCode.push_back(
            mk(cursor, 4, "lea", "r8, [rbp - 0x80]"));
        cursor += 4;
        cappedCallCode.push_back(mk(cursor, 5, "mov", "edx, 0x65"));
        cursor += 5;
        cappedCallCode.push_back(mk(cursor, 3, "mov", "rcx, rbx"));
        cursor += 3;
        cappedCallCode.push_back(mk(cursor, 6, "mov", "r9d, 0x40"));
        cursor += 6;
        const uint64_t postClassificationProducerVA = cursor;
        cappedCallCode.push_back(
            mk(cursor, 5, "call", "0x8000", true, false, 0x8000));
        cursor += 5;
        cappedCallCode.push_back(mk(cursor, 1, "ret", "", true, true));
        FuncAnnotations cappedCalls = annotate(cappedCallCode, o);
        CHECK(!cappedCalls.complete);
        CHECK(has(cappedCalls.incompleteReason, "classification cap"));
        CHECK(has(cappedCalls.incompleteReason,
                  "local input decisions may be omitted"));
        const ApiCallObservation* unclassifiedProducer =
            findCall(cappedCalls, postClassificationProducerVA);
        CHECK(unclassifiedProducer != nullptr);
        if (unclassifiedProducer)
            CHECK(!unclassifiedProducer->localInputDecisionAnalysisAttempted);

        // A sink beyond the four-block trace depth is omitted and disclosed,
        // never silently treated as proof that no further decision exists.
        ControlFlowGraph depthGraph;
        depthGraph.funcStart = 0xF000;
        BasicBlock depthProducer;
        depthProducer.start = 0xF000;
        depthProducer.end = 0xF017;
        depthProducer.insns = {
            mk(0xF000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0xF004, 5, "mov",  "edx, 0x65"),
            mk(0xF009, 3, "mov",  "rcx, rbx"),
            mk(0xF00C, 6, "mov",  "r9d, 0x40"),
            mk(0xF012, 5, "call", "0x8000", true, false, 0x8000),
        };
        depthProducer.succ = {1};
        depthGraph.blocks.push_back(std::move(depthProducer));
        for (size_t blockIndex = 1; blockIndex <= 4; ++blockIndex) {
            BasicBlock transit;
            transit.start = 0xF000 + blockIndex * 0x10;
            transit.end = transit.start + 1;
            transit.insns = {mk(transit.start, 1, "nop", "")};
            transit.succ = {blockIndex + 1};
            depthGraph.blocks.push_back(std::move(transit));
        }
        BasicBlock depthSink;
        depthSink.start = 0xF060;
        depthSink.end = 0xF075;
        depthSink.insns = {
            mk(0xF060, 7, "mov",  "rdx, 0x9000"),
            mk(0xF067, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0xF06B, 5, "call", "0x8100", true, false, 0x8100),
            mk(0xF070, 2, "test", "eax, eax"),
            mk(0xF072, 2, "je",   "0xF078", true, false, 0xF078),
        };
        depthSink.transferIndex = depthSink.insns.size() - 1;
        depthGraph.blocks.push_back(std::move(depthSink));
        FuncAnnotations depthCapped = AnnotateFunction(depthGraph, o);
        const ApiCallObservation* depthInput = findCall(depthCapped, 0xF012);
        CHECK(depthInput != nullptr);
        if (depthInput) {
            CHECK(depthInput->localInputDecisionAnalysisAttempted);
            CHECK(!depthInput->localInputDecisionsComplete);
            CHECK(depthInput->localInputDecisions.empty());
            CHECK(has(depthInput->localInputDecisionIncompleteReason,
                      "block, or state limit"));
        }

        // A nonvolatile register loaded before the input API still contains
        // stale bytes after the call. Backward inline provenance must stop at
        // the exact producer call instead of attributing that value to new input.
        FuncAnnotations staleRegister = annotate({
            mk(0x11000, 4, "movzx", "ebx, byte ptr [rbp - 0x80]"),
            mk(0x11004, 4, "lea",   "r8, [rbp - 0x80]"),
            mk(0x11008, 5, "mov",   "edx, 0x65"),
            mk(0x1100D, 3, "mov",   "rcx, rbx"),
            mk(0x11010, 6, "mov",   "r9d, 0x40"),
            mk(0x11016, 5, "call",  "0x8000", true, false, 0x8000),
            mk(0x1101B, 3, "cmp",   "bl, 0x41"),
            mk(0x1101E, 2, "je",    "0x11028", true, false, 0x11028),
            mk(0x11020, 1, "ret",   "", true, true),
            mk(0x11028, 1, "ret",   "", true, true),
        }, o);
        const ApiCallObservation* staleRegisterInput =
            findCall(staleRegister, 0x11016);
        CHECK(staleRegisterInput != nullptr);
        if (staleRegisterInput) {
            CHECK(staleRegisterInput->localInputDecisionAnalysisAttempted);
            CHECK(staleRegisterInput->localInputDecisionsComplete);
            CHECK(staleRegisterInput->localInputDecisions.empty());
        }

        // Comparator-result aliases are path-local. A copy created only in the
        // lower-address successor cannot make a disjoint successor's rbx test
        // consume strcmp's result.
        ControlFlowGraph disjointGraph;
        disjointGraph.funcStart = 0x12000;
        BasicBlock split;
        split.start = 0x12000;
        split.end = 0x1202D;
        split.insns = {
            mk(0x12000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0x12004, 5, "mov",  "edx, 0x65"),
            mk(0x12009, 3, "mov",  "rcx, rbx"),
            mk(0x1200C, 6, "mov",  "r9d, 0x40"),
            mk(0x12012, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x12017, 7, "mov",  "rdx, 0x9000"),
            mk(0x1201E, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x12022, 5, "call", "0x8100", true, false, 0x8100),
            mk(0x12027, 4, "cmp",  "r10d, 0"),
            mk(0x1202B, 2, "jne",  "0x12050", true, false, 0x12050),
        };
        split.transferIndex = split.insns.size() - 1;
        split.succ = {1, 2};
        disjointGraph.blocks.push_back(std::move(split));

        BasicBlock aliasOnlyPath;
        aliasOnlyPath.start = 0x12030;
        aliasOnlyPath.end = 0x12034;
        aliasOnlyPath.insns = {
            mk(0x12030, 3, "mov", "rbx, rax"),
            mk(0x12033, 1, "ret", "", true, true),
        };
        aliasOnlyPath.isReturn = true;
        disjointGraph.blocks.push_back(std::move(aliasOnlyPath));

        BasicBlock impossibleUsePath;
        impossibleUsePath.start = 0x12050;
        impossibleUsePath.end = 0x12055;
        impossibleUsePath.insns = {
            mk(0x12050, 3, "test", "rbx, rbx"),
            mk(0x12053, 2, "je",   "0x12060", true, false, 0x12060),
        };
        impossibleUsePath.transferIndex = impossibleUsePath.insns.size() - 1;
        disjointGraph.blocks.push_back(std::move(impossibleUsePath));

        FuncAnnotations disjoint = AnnotateFunction(disjointGraph, o);
        const ApiCallObservation* disjointInput = findCall(disjoint, 0x12012);
        CHECK(disjointInput != nullptr);
        if (disjointInput) {
            CHECK(disjointInput->localInputDecisionAnalysisAttempted);
            CHECK(disjointInput->localInputDecisionsComplete);
            CHECK(disjointInput->localInputDecisions.empty());
        }

        // strncmp and memcmp describe only the exact recovered prefix. They
        // must not render the resolver's full string when the bound is smaller.
        FuncAnnotations boundedPrefix = annotate({
            mk(0x13000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0x13004, 5, "mov",  "edx, 0x65"),
            mk(0x13009, 3, "mov",  "rcx, rbx"),
            mk(0x1300C, 6, "mov",  "r9d, 0x40"),
            mk(0x13012, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x13017, 6, "mov",  "r8d, 2"),
            mk(0x1301D, 7, "mov",  "rdx, 0x9300"),
            mk(0x13024, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x13028, 5, "call", "0x8400", true, false, 0x8400),
            mk(0x1302D, 2, "test", "eax, eax"),
            mk(0x1302F, 2, "je",   "0x13038", true, false, 0x13038),
            mk(0x13031, 1, "ret",  "", true, true),
            mk(0x13038, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* boundedPrefixInput =
            findCall(boundedPrefix, 0x13012);
        CHECK(boundedPrefixInput != nullptr);
        if (boundedPrefixInput &&
            boundedPrefixInput->localInputDecisions.size() == 1) {
            const ApiLocalInputDecisionObservation& decision =
                boundedPrefixInput->localInputDecisions.front();
            CHECK(has(decision.expectedValue, "\"OP\""));
            CHECK(has(decision.expectedValue, "first 2 byte"));
            CHECK(!has(decision.expectedValue, "OPEN"));
        } else {
            CHECK(false);
        }

        FuncAnnotations boundedBytes = annotate({
            mk(0x14000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0x14004, 5, "mov",  "edx, 0x65"),
            mk(0x14009, 3, "mov",  "rcx, rbx"),
            mk(0x1400C, 6, "mov",  "r9d, 0x40"),
            mk(0x14012, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x14017, 6, "mov",  "r8d, 2"),
            mk(0x1401D, 7, "mov",  "rdx, 0x9300"),
            mk(0x14024, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x14028, 5, "call", "0x8600", true, false, 0x8600),
            mk(0x1402D, 2, "test", "eax, eax"),
            mk(0x1402F, 2, "je",   "0x14038", true, false, 0x14038),
            mk(0x14031, 1, "ret",  "", true, true),
            mk(0x14038, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* boundedBytesInput =
            findCall(boundedBytes, 0x14012);
        CHECK(boundedBytesInput != nullptr);
        if (boundedBytesInput &&
            boundedBytesInput->localInputDecisions.size() == 1) {
            const ApiLocalInputDecisionObservation& decision =
                boundedBytesInput->localInputDecisions.front();
            CHECK(has(decision.expectedValue, "\"OP\""));
            CHECK(!has(decision.expectedValue, "OPEN"));
        } else {
            CHECK(false);
        }

        // The resolver exposes only two bytes here, while memcmp reads four.
        // Those additional bytes cannot be represented exactly, so abstain.
        FuncAnnotations unrepresentableBytes = annotate({
            mk(0x15000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0x15004, 5, "mov",  "edx, 0x65"),
            mk(0x15009, 3, "mov",  "rcx, rbx"),
            mk(0x1500C, 6, "mov",  "r9d, 0x40"),
            mk(0x15012, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x15017, 6, "mov",  "r8d, 4"),
            mk(0x1501D, 7, "mov",  "rdx, 0x9400"),
            mk(0x15024, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x15028, 5, "call", "0x8600", true, false, 0x8600),
            mk(0x1502D, 2, "test", "eax, eax"),
            mk(0x1502F, 2, "je",   "0x15038", true, false, 0x15038),
            mk(0x15031, 1, "ret",  "", true, true),
            mk(0x15038, 1, "ret",  "", true, true),
        }, o);
        const ApiCallObservation* unrepresentableInput =
            findCall(unrepresentableBytes, 0x15012);
        CHECK(unrepresentableInput != nullptr);
        if (unrepresentableInput) {
            CHECK(unrepresentableInput->localInputDecisionAnalysisAttempted);
            CHECK(unrepresentableInput->localInputDecisionsComplete);
            CHECK(unrepresentableInput->localInputDecisions.empty());
        }

        // Branch fallthrough uses checked address arithmetic. A two-byte branch
        // at UINT64_MAX-1 cannot fabricate a valid VA-zero fallthrough.
        ControlFlowGraph overflowGraph;
        overflowGraph.funcStart = 0x1000;
        BasicBlock overflowBlock;
        overflowBlock.start = 0x1000;
        overflowBlock.insns = {
            mk(0x1000, 4, "lea",  "r8, [rbp - 0x80]"),
            mk(0x1004, 5, "mov",  "edx, 0x65"),
            mk(0x1009, 3, "mov",  "rcx, rbx"),
            mk(0x100C, 6, "mov",  "r9d, 0x40"),
            mk(0x1012, 5, "call", "0x8000", true, false, 0x8000),
            mk(0x1017, 7, "mov",  "rdx, 0x9000"),
            mk(0x101E, 4, "lea",  "rcx, [rbp - 0x80]"),
            mk(0x1022, 5, "call", "0x8100", true, false, 0x8100),
            mk(0x1027, 2, "test", "eax, eax"),
            mk((std::numeric_limits<uint64_t>::max)() - 1, 2,
               "je", "0x1234", true, false, 0x1234),
        };
        overflowBlock.transferIndex = overflowBlock.insns.size() - 1;
        overflowBlock.end = (std::numeric_limits<uint64_t>::max)();
        overflowGraph.blocks.push_back(std::move(overflowBlock));
        FuncAnnotations overflow = AnnotateFunction(overflowGraph, o);
        const ApiCallObservation* overflowInput = findCall(overflow, 0x1012);
        CHECK(overflowInput != nullptr);
        if (overflowInput && overflowInput->localInputDecisions.size() == 1) {
            const ApiLocalInputDecisionObservation& decision =
                overflowInput->localInputDecisions.front();
            CHECK(decision.decisionVAValid);
            CHECK(decision.decisionVA ==
                  (std::numeric_limits<uint64_t>::max)() - 1);
            CHECK(!decision.fallthroughVAValid);
            CHECK(decision.fallthroughVA == 0);
            CHECK(!decision.mismatchVAValid);
        } else {
            CHECK(false);
        }
    }

    // 19) Instruction VA zero remains a real source location, while function-level
    // findings use an explicit invalid source. Ownership/provenance metadata is
    // retained in the result and its divider summary.
    {
        AnnotateOptions o;
        o.chunks = {{0, 5}, {0x20, 1}};
        o.ownershipTruncated = true;
        o.seedKind = FunctionSeedKind::Analyst;
        o.boundaryConfidence = FunctionBoundaryConfidence::Authoritative;
        FuncAnnotations a = annotate({
            mk(0, 1, "push", "rbp"),
            mk(1, 3, "mov", "rbp, rsp"),
            mk(4, 1, "ret", "", true, true),
        }, o);
        const FnNote* prologue = findNote(a, NoteKind::Prologue);
        CHECK(prologue && prologue->sourceValid && prologue->va == 0);
        CHECK(a.chunks.size() == 2);
        CHECK(a.ownershipTruncated);
        CHECK(a.seedKind == FunctionSeedKind::Analyst);
        CHECK(a.boundaryConfidence == FunctionBoundaryConfidence::Authoritative);
        CHECK(has(a.summary, "authoritative boundary"));
        CHECK(has(a.summary, "analyst seed"));
        CHECK(has(a.summary, "2 chunks"));
        CHECK(has(a.summary, "ownership truncated"));
        bool lifetimeAtZero = false;
        for (const RegLifetime& lifetime : a.regs)
            if (lifetime.reg == "rbp") {
                lifetimeAtZero = true;
                CHECK(lifetime.firstVA == 0);
                CHECK(lifetime.lastVA == 1);
            }
        CHECK(lifetimeAtZero);
    }

    // 20) Typed return and formal-field facts are conservative, validity-bearing,
    // and independent of the human-readable annotations above.
    {
        auto typedMovImmediate = [](uint64_t address, uint64_t value) {
            Instruction instruction = mk(address, 5, "mov", "<opaque>");
            instruction.typedOperands = {
                regOp("eax", OperandAccess::Write, 32),
                immOp(value, 32),
            };
            instruction.registersWritten = {"eax"};
            return instruction;
        };

        // Two distinct exits that return exactly 0 and 1 form one canonical
        // boolean function. The exits remain separate observations.
        ControlFlowGraph booleanGraph;
        booleanGraph.funcStart = 0x2000;
        BasicBlock split;
        split.start = 0x2000;
        split.end = 0x2004;
        Instruction inputTest = mk(0x2000, 2, "test", "<opaque>");
        inputTest.typedOperands = {
            regOp("ecx", OperandAccess::Read, 32),
            regOp("ecx", OperandAccess::Read, 32),
        };
        inputTest.registersRead = {"ecx"};
        inputTest.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
        Instruction chooseTrue = mk(0x2002, 2, "jne", "<opaque>",
                                    false, false, 0x2020);
        chooseTrue.flow.kind = FlowKind::ConditionalBranch;
        chooseTrue.flow.directTargetValid = true;
        chooseTrue.flow.directTarget = 0x2020;
        chooseTrue.flagsRead = SemanticFlagBit(SemanticFlag::Zero);
        split.insns = {inputTest, chooseTrue};
        split.transferIndex = 1;
        split.succ = {1, 2};
        booleanGraph.blocks.push_back(std::move(split));

        BasicBlock falseExit;
        falseExit.start = 0x2010;
        falseExit.end = 0x2016;
        falseExit.insns = {
            typedMovImmediate(0x2010, 0),
            mk(0x2015, 1, "ret", "", true, true),
        };
        falseExit.isReturn = true;
        booleanGraph.blocks.push_back(std::move(falseExit));

        BasicBlock trueExit;
        trueExit.start = 0x2020;
        trueExit.end = 0x2026;
        trueExit.insns = {
            typedMovImmediate(0x2020, 1),
            mk(0x2025, 1, "ret", "", true, true),
        };
        trueExit.isReturn = true;
        booleanGraph.blocks.push_back(std::move(trueExit));

        FuncAnnotations booleanResult = AnnotateFunction(booleanGraph, {});
        CHECK(booleanResult.returnObservation.analysisAttempted);
        CHECK(booleanResult.returnObservation.complete);
        CHECK(booleanResult.returnObservation.kind ==
              FunctionReturnKind::CanonicalBoolean);
        CHECK(booleanResult.returnObservation.validWidthKnown);
        CHECK(booleanResult.returnObservation.validWidthBits == 32);
        CHECK(booleanResult.returnObservation.exits.size() == 2);
        if (booleanResult.returnObservation.exits.size() == 2) {
            CHECK(booleanResult.returnObservation.exits[0].returnVAValid);
            CHECK(booleanResult.returnObservation.exits[0].constantValueValid);
            CHECK(booleanResult.returnObservation.exits[0].constantValue == 0);
            CHECK(booleanResult.returnObservation.exits[1].constantValueValid);
            CHECK(booleanResult.returnObservation.exits[1].constantValue == 1);
        }

        FuncAnnotations nonBoolean = annotateCompleteBlock({
            typedMovImmediate(0x2100, 2),
            mk(0x2105, 1, "ret", "", true, true),
        });
        CHECK(!nonBoolean.returnObservation.complete);
        CHECK(nonBoolean.returnObservation.kind == FunctionReturnKind::Unknown);
        CHECK(nonBoolean.returnObservation.exits.size() == 1);
        if (nonBoolean.returnObservation.exits.size() == 1)
            CHECK(nonBoolean.returnObservation.exits[0].kind ==
                  FunctionReturnKind::Unknown);

        FuncAnnotations unknown = annotateCompleteBlock({
            mk(0x2200, 1, "ret", "", true, true),
        });
        CHECK(!unknown.returnObservation.complete);
        CHECK(unknown.returnObservation.kind == FunctionReturnKind::Unknown);
        CHECK(has(unknown.returnObservation.incompleteReason, "unknown value"));

        Instruction setCondition = mk(0x2300, 3, "setne", "<opaque>");
        setCondition.typedOperands = {
            regOp("al", OperandAccess::Write, 8),
        };
        setCondition.registersWritten = {"al"};
        setCondition.flagsRead = SemanticFlagBit(SemanticFlag::Zero);
        FuncAnnotations materialized = annotateCompleteBlock({
            setCondition,
            mk(0x2303, 1, "ret", "", true, true),
        });
        CHECK(materialized.returnObservation.complete);
        CHECK(materialized.returnObservation.kind ==
              FunctionReturnKind::MaterializedCondition);
        CHECK(materialized.returnObservation.validWidthKnown);
        CHECK(materialized.returnObservation.validWidthBits == 8);

        Instruction fieldGetter = mk(0x2400, 7, "movzx", "<opaque>");
        fieldGetter.typedOperands = {
            regOp("eax", OperandAccess::Write, 32),
            memOp("rcx", 0x138, OperandAccess::Read, 8),
        };
        fieldGetter.registersRead = {"rcx"};
        fieldGetter.registersWritten = {"eax"};
        FuncAnnotations getter = annotateCompleteBlock({
            fieldGetter,
            mk(0x2407, 1, "ret", "", true, true),
        });
        CHECK(getter.fieldAccesses.size() == 1);
        if (getter.fieldAccesses.size() == 1) {
            const ObjectFieldAccessObservation& field = getter.fieldAccesses[0];
            CHECK(field.functionVAValid && field.functionVA == 0x2400);
            CHECK(field.instructionVAValid && field.instructionVA == 0x2400);
            CHECK(field.operandIndex == 1);
            CHECK(field.rootParameterIndex == 0);
            CHECK(field.rootAbiLocation == "rcx");
            CHECK(field.displacementValid && field.displacement == 0x138);
            CHECK(field.widthKnown && field.widthBits == 8);
            CHECK(field.access == ObjectFieldAccessKind::Read);
            CHECK(field.exact);
            CHECK(!field.evidence.empty());
        }
        CHECK(getter.returnObservation.complete);
        CHECK(getter.returnObservation.kind ==
              FunctionReturnKind::FieldBackedBoolean);
        CHECK(getter.returnObservation.exits.size() == 1);
        if (getter.returnObservation.exits.size() == 1) {
            CHECK(getter.returnObservation.exits[0].fieldAccessIndexValid);
            CHECK(getter.returnObservation.exits[0].validWidthBits == 8);
        }

        // Copies of the formal receiver remain rooted in parameter zero. A
        // read and a write to the same displacement stay as two exact facts.
        Instruction saveReceiver = mk(0x2500, 3, "mov", "<opaque>");
        saveReceiver.typedOperands = {
            regOp("rbx", OperandAccess::Write, 64),
            regOp("rcx", OperandAccess::Read, 64),
        };
        saveReceiver.registersRead = {"rcx"};
        saveReceiver.registersWritten = {"rbx"};
        Instruction fieldRead = mk(0x2503, 7, "movzx", "<opaque>");
        fieldRead.typedOperands = {
            regOp("edx", OperandAccess::Write, 32),
            memOp("rbx", 0x138, OperandAccess::Read, 8),
        };
        fieldRead.registersRead = {"rbx"};
        fieldRead.registersWritten = {"edx"};
        Instruction fieldWrite = mk(0x250A, 7, "mov", "<opaque>");
        fieldWrite.typedOperands = {
            memOp("rbx", 0x138, OperandAccess::Write, 8),
            regOp("dl", OperandAccess::Read, 8),
        };
        fieldWrite.registersRead = {"rbx", "dl"};
        Instruction returnZero = mk(0x2511, 2, "xor", "<opaque>");
        returnZero.typedOperands = {
            regOp("eax", OperandAccess::ReadWrite, 32),
            regOp("eax", OperandAccess::Read, 32),
        };
        returnZero.registersRead = {"eax"};
        returnZero.registersWritten = {"eax"};
        FuncAnnotations fields = annotateCompleteBlock({
            saveReceiver,
            fieldRead,
            fieldWrite,
            returnZero,
            mk(0x2513, 1, "ret", "", true, true),
        });
        CHECK(fields.fieldAccesses.size() == 2);
        if (fields.fieldAccesses.size() == 2) {
            CHECK(fields.fieldAccesses[0].rootParameterIndex == 0);
            CHECK(fields.fieldAccesses[0].displacement == 0x138);
            CHECK(fields.fieldAccesses[0].access == ObjectFieldAccessKind::Read);
            CHECK(fields.fieldAccesses[1].rootParameterIndex == 0);
            CHECK(fields.fieldAccesses[1].displacement == 0x138);
            CHECK(fields.fieldAccesses[1].access == ObjectFieldAccessKind::Write);
        }

        AnnotateOptions namedCall;
        namedCall.nameFor = [](uint64_t address) {
            return address == 0 ? std::string("license.IsSigned")
                                : std::string();
        };
        Instruction zeroAddressCall = mk(0, 5, "call", "<opaque>",
                                         true, false, 0);
        zeroAddressCall.flow.kind = FlowKind::DirectCall;
        zeroAddressCall.flow.directTargetValid = true;
        zeroAddressCall.flow.directTarget = 0;
        FuncAnnotations forwarded = annotateCompleteBlock({
            zeroAddressCall,
            mk(5, 1, "ret", "", true, true),
        }, namedCall);
        CHECK(forwarded.returnObservation.complete);
        CHECK(forwarded.returnObservation.kind == FunctionReturnKind::ForwardedCall);
        CHECK(forwarded.returnObservation.exits.size() == 1);
        if (forwarded.returnObservation.exits.size() == 1) {
            const FunctionReturnExitObservation& exit =
                forwarded.returnObservation.exits[0];
            CHECK(exit.forwardedCallVAValid && exit.forwardedCallVA == 0);
            CHECK(exit.forwardedTargetVAValid && exit.forwardedTargetVA == 0);
            CHECK(exit.forwardedName == "license.IsSigned");
        }
    }

    // 21) Exact x64 formal-root bindings are emitted from the CFG must-dataflow
    // pass before a direct call clobbers volatile registers.
    {
        AnnotateOptions internal;
        internal.isInternalFunction = [](uint64_t address) {
            return address == 0x5000 || address == 0x7000;
        };
        internal.internalFunctionMembershipComplete = true;

        Instruction zeroCall = mk(0, 5, "call", "0x5000", true, false,
                                  0x5000);
        zeroCall.flow.kind = FlowKind::DirectCall;
        zeroCall.flow.directTargetValid = true;
        zeroCall.flow.directTarget = 0x5000;
        FuncAnnotations zero = annotateCompleteBlock({
            zeroCall,
            mk(5, 1, "ret", "", true, true),
        }, internal);
        CHECK(zero.directCallFormalBindingAnalysisAttempted);
        CHECK(zero.directCallFormalBindingsComplete);
        CHECK(zero.directCallFormalBindings.size() == 4);
        const auto* zeroBinding = findFormalBinding(zero, 0, 0);
        CHECK(zeroBinding != nullptr);
        if (zeroBinding) {
            CHECK(zeroBinding->callerFunctionVAValid &&
                  zeroBinding->callerFunctionVA == 0);
            CHECK(zeroBinding->callVAValid && zeroBinding->callVA == 0);
            CHECK(zeroBinding->calleeFunctionVAValid &&
                  zeroBinding->calleeFunctionVA == 0x5000);
            CHECK(zeroBinding->callerRootParameterIndex == 0);
            CHECK(zeroBinding->callerRootBiasValid &&
                  zeroBinding->callerRootBias == 0);
            CHECK(zeroBinding->directCallTargetExact);
            CHECK(zeroBinding->argumentRootExact);
            CHECK(!zeroBinding->evidence.empty());
        }

        Instruction copy = mk(0x6100, 3, "mov", "<opaque>");
        copy.typedOperands = {
            regOp("rdx", OperandAccess::Write, 64),
            regOp("rcx", OperandAccess::Read, 64),
        };
        copy.registersRead = {"rcx"};
        copy.registersWritten = {"rdx"};
        Instruction adjusted = mk(0x6103, 4, "lea", "<opaque>");
        adjusted.typedOperands = {
            regOp("r8", OperandAccess::Write, 64),
            memOp("rcx", 0x20, OperandAccess::Read, 64),
        };
        adjusted.registersRead = {"rcx"};
        adjusted.registersWritten = {"r8"};
        Instruction clearR9 = mk(0x6107, 3, "xor", "<opaque>");
        clearR9.typedOperands = {
            regOp("r9d", OperandAccess::ReadWrite, 32),
            regOp("r9d", OperandAccess::Read, 32),
        };
        clearR9.registersRead = {"r9d"};
        clearR9.registersWritten = {"r9d"};
        Instruction copiedCall = mk(0x610A, 5, "call", "0x7000",
                                    true, false, 0x7000);
        copiedCall.flow.kind = FlowKind::DirectCall;
        copiedCall.flow.directTargetValid = true;
        copiedCall.flow.directTarget = 0x7000;
        FuncAnnotations copied = annotateCompleteBlock({
            copy, adjusted, clearR9, copiedCall,
            mk(0x610F, 1, "ret", "", true, true),
        }, internal);
        CHECK(copied.directCallFormalBindingsComplete);
        CHECK(copied.directCallFormalBindings.size() == 2);
        const auto* receiver = findFormalBinding(copied, 0x610A, 0);
        const auto* copiedReceiver = findFormalBinding(copied, 0x610A, 1);
        CHECK(receiver && receiver->callerRootParameterIndex == 0);
        CHECK(copiedReceiver && copiedReceiver->callerRootParameterIndex == 0);
        CHECK(findFormalBinding(copied, 0x610A, 2) == nullptr); // +0x20 root
        CHECK(findFormalBinding(copied, 0x610A, 3) == nullptr); // overwritten

        Instruction legacyGuess = mk(0x6200, 5, "call", "0x7000",
                                     true, false, 0x7000);
        FuncAnnotations guessed = annotateCompleteBlock({
            legacyGuess,
            mk(0x6205, 1, "ret", "", true, true),
        }, internal);
        CHECK(guessed.directCallFormalBindingsComplete);
        CHECK(guessed.directCallFormalBindings.empty());

        Instruction externalCall = mk(0x6300, 5, "call", "0x9000",
                                      true, false, 0x9000);
        externalCall.flow.kind = FlowKind::DirectCall;
        externalCall.flow.directTargetValid = true;
        externalCall.flow.directTarget = 0x9000;
        FuncAnnotations external = annotateCompleteBlock({
            externalCall,
            mk(0x6305, 1, "ret", "", true, true),
        }, internal);
        CHECK(external.directCallFormalBindingsComplete);
        CHECK(external.directCallFormalBindings.empty());

        AnnotateOptions partialMembership = internal;
        partialMembership.internalFunctionMembershipComplete = false;
        FuncAnnotations partial = annotateCompleteBlock({
            zeroCall,
            mk(5, 1, "ret", "", true, true),
        }, partialMembership);
        CHECK(!partial.directCallFormalBindingsComplete);
        CHECK(partial.directCallFormalBindings.size() == 4);
        CHECK(has(partial.directCallFormalBindingIncompleteReason,
                  "scope was incomplete"));

        FuncAnnotations noClassifier = annotateCompleteBlock({
            externalCall,
            mk(0x6305, 1, "ret", "", true, true),
        });
        CHECK(!noClassifier.directCallFormalBindingsComplete);
        CHECK(has(noClassifier.directCallFormalBindingIncompleteReason,
                  "classifier"));

        AnnotateOptions x86 = internal;
        x86.x64 = false;
        FuncAnnotations unsupported = annotateCompleteBlock({
            externalCall,
            mk(0x6305, 1, "ret", "", true, true),
        }, x86);
        CHECK(!unsupported.directCallFormalBindingsComplete);
        CHECK(has(unsupported.directCallFormalBindingIncompleteReason,
                  "only for x64"));

        AnnotateOptions throwing = internal;
        throwing.isInternalFunction = [](uint64_t) -> bool {
            throw 1;
        };
        FuncAnnotations failedClassifier = annotateCompleteBlock({
            zeroCall,
            mk(5, 1, "ret", "", true, true),
        }, throwing);
        CHECK(!failedClassifier.directCallFormalBindingsComplete);
        CHECK(failedClassifier.directCallFormalBindings.empty());
        CHECK(has(failedClassifier.directCallFormalBindingIncompleteReason,
                  "classifier failed"));
    }

    // 22) Enum display names cover every kind with a non-fallback label.
    for (int k = 0; k <= (int)NoteKind::Pattern; ++k)
        CHECK(std::string(NoteKindName((NoteKind)k)) != "?");
    for (int k = 0; k <= (int)FunctionReturnKind::ForwardedCall; ++k)
        CHECK(std::string(FunctionReturnKindName((FunctionReturnKind)k)) != "unknown" ||
              k == (int)FunctionReturnKind::Unknown);
    for (int k = 0; k <= (int)ObjectFieldAccessKind::ReadWrite; ++k)
        CHECK(std::string(ObjectFieldAccessKindName((ObjectFieldAccessKind)k)) != "unknown");

    if (g_fail == 0) std::printf("funcannotate_test: ALL PASS\n");
    else             std::printf("funcannotate_test: %d FAIL\n", g_fail);
    return g_fail ? 1 : 0;
}
