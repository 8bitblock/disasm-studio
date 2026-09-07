#include "Core/ValueOrigin.h"
#include <cstdio>

using namespace ds;
static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)

static TypedOperand reg(const char* name, OperandAccess access) {
    TypedOperand result; result.kind = OperandKind::Register; result.access = access;
    result.registerName = name;
    result.widthBits = DescribeRegisterSlice(name, 0, Arch::X64).widthBits;
    return result;
}
static TypedOperand imm(uint64_t n) {
    TypedOperand result; result.kind = OperandKind::Immediate; result.access = OperandAccess::Read;
    result.immediate = n; return result;
}
static Instruction ins(uint64_t va, const char* mnemonic, std::initializer_list<TypedOperand> operands = {}) {
    Instruction result; result.address = va; result.length = 1; result.mnemonic = mnemonic;
    result.typedOperands = operands; return result;
}
static Instruction constant(uint64_t va, const char* name, uint64_t value = 1) {
    return ins(va, "mov", {reg(name, OperandAccess::Write), imm(value)});
}
static Instruction copy(uint64_t va, const char* dest, const char* source) {
    return ins(va, "mov", {reg(dest, OperandAccess::Write), reg(source, OperandAccess::Read)});
}
static BasicBlock block(uint64_t va, std::initializer_list<Instruction> instructions,
                        std::initializer_list<size_t> succ = {}) {
    BasicBlock result; result.start = va; result.insns = instructions; result.succ = succ; return result;
}
static ControlFlowGraph graph(std::initializer_list<BasicBlock> blocks) {
    ControlFlowGraph result; result.blocks = blocks; result.funcStart = result.blocks.front().start; return result;
}
static bool source(const ValueOriginResult& r, uint64_t va) {
    return std::any_of(r.sources.begin(), r.sources.end(), [&](const auto& s) { return s.va == va; });
}
static bool boundary(const ValueOriginResult& r, ValueOriginBoundaryKind kind) {
    return std::any_of(r.boundaries.begin(), r.boundaries.end(), [&](const auto& b) { return b.kind == kind; });
}

int main() {
    {
        auto g = graph({block(0, {constant(0, "eax"), copy(1, "ecx", "eax"), ins(2, "nop")})});
        auto r = TraceValueOrigin(g, Arch::X64, 2, "ecx");
        CHECK(r.valid && r.complete && source(r, 0) && source(r, 1));
        CHECK(r.sources.size() == 2); // source at VA zero is real.
        r = TraceValueOrigin(g, Arch::X64, 1, "ecx");
        CHECK(r.valid && !r.complete && !source(r, 1)); // before, not after selected MOV.
        CHECK(boundary(r, ValueOriginBoundaryKind::Incoming));
    }
    {
        auto g = graph({block(0, {constant(0, "rax"), constant(1, "al"), ins(2, "nop")})});
        auto r = TraceValueOrigin(g, Arch::X64, 2, "ah");
        CHECK(r.complete && source(r, 0) && !source(r, 1));
        r = TraceValueOrigin(g, Arch::X64, 2, "rax");
        CHECK(r.complete && source(r, 0) && source(r, 1));
        g.blocks[0].insns[1] = constant(1, "eax");
        r = TraceValueOrigin(g, Arch::X64, 2, "rax");
        CHECK(r.complete && !source(r, 0) && source(r, 1)); // EAX defines all RAX.
    }
    {
        auto g = graph({block(0, {constant(0, "ah"), copy(1, "al", "ah"), ins(2, "nop")})});
        auto r = TraceValueOrigin(g, Arch::X64, 2, "al");
        CHECK(r.complete && source(r, 0) && source(r, 1)); // high-byte offsets map correctly.
    }
    {
        auto g = graph({block(0, {constant(0, "al"),
            ins(1, "movzx", {reg("eax", OperandAccess::Write), reg("al", OperandAccess::Read)}), ins(2, "nop")})});
        auto r = TraceValueOrigin(g, Arch::X64, 2, "ah");
        CHECK(r.complete && source(r, 1) && !source(r, 0)); // zero-extended bits don't depend on AL.
        g.blocks[0].insns[1].mnemonic = "movsx";
        r = TraceValueOrigin(g, Arch::X64, 2, "ah");
        CHECK(r.complete && source(r, 0) && source(r, 1)); // sign bit does.
    }
    {
        auto g = graph({block(0, {constant(0, "eax")}, {1, 2}),
            block(10, {constant(10, "eax")}, {3}), block(20, {constant(20, "eax")}, {3}),
            block(30, {ins(30, "nop")})});
        auto r = TraceValueOrigin(g, Arch::X64, 30, "eax");
        CHECK(r.valid && !r.complete && source(r, 10) && source(r, 20) && !source(r, 0));
        CHECK(boundary(r, ValueOriginBoundaryKind::Join));
        // Unreachable predecessor must not manufacture a source.
        g.blocks[0].succ = {1};
        r = TraceValueOrigin(g, Arch::X64, 30, "eax");
        CHECK(r.complete && source(r, 10) && !source(r, 20));
    }
    {
        auto g = graph({block(0, {constant(0, "eax")}, {1}),
            block(10, {ins(10, "nop"), ins(11, "add", {reg("eax", OperandAccess::ReadWrite), imm(1)})}, {1})});
        auto r = TraceValueOrigin(g, Arch::X64, 10, "eax");
        CHECK(r.valid && !r.complete && source(r, 0) && source(r, 11));
        CHECK(boundary(r, ValueOriginBoundaryKind::Cycle));
    }
    {
        TypedOperand memory; memory.kind = OperandKind::Memory; memory.access = OperandAccess::Read;
        memory.baseRegister = "rcx"; memory.widthBits = 32;
        auto g = graph({block(0, {constant(0, "rcx"), ins(1, "mov", {reg("eax", OperandAccess::Write), memory}), ins(2, "nop")})});
        auto r = TraceValueOrigin(g, Arch::X64, 2, "eax");
        CHECK(!r.complete && source(r, 1) && !source(r, 0));
        CHECK(boundary(r, ValueOriginBoundaryKind::Memory));
        g.blocks[0].insns[1].mnemonic = "lea";
        r = TraceValueOrigin(g, Arch::X64, 2, "eax");
        CHECK(r.complete && source(r, 0) && source(r, 1));
    }
    {
        auto g = graph({block(0, {constant(0, "eax"), ins(1, "call"), ins(2, "nop")})});
        g.blocks[0].insns[1].flow.kind = FlowKind::IndirectCall;
        auto r = TraceValueOrigin(g, Arch::X64, 2, "eax");
        CHECK(!r.complete && !source(r, 0) && boundary(r, ValueOriginBoundaryKind::Call));
        g.blocks[0].insns[1] = ins(1, "bswap", {reg("eax", OperandAccess::ReadWrite)});
        r = TraceValueOrigin(g, Arch::X64, 2, "eax");
        CHECK(!r.complete && r.sources.empty() && boundary(r, ValueOriginBoundaryKind::Unsupported));
        g.blocks[0].insns[1] = ins(1, "xor", {reg("eax", OperandAccess::ReadWrite), reg("eax", OperandAccess::Read)});
        r = TraceValueOrigin(g, Arch::X64, 2, "eax");
        CHECK(r.complete && source(r, 1) && !source(r, 0));
    }
    {
        auto g = graph({block(0, {constant(0, "eax"), copy(1, "ecx", "eax"), ins(2, "nop")})});
        auto r = TraceValueOrigin(g, Arch::X86, 2, "ecx");
        CHECK(r.complete && source(r, 0));
        CHECK(!TraceValueOrigin(g, Arch::X86, 2, "rax").valid);
        CHECK(!TraceValueOrigin(g, Arch::ARM64, 2, "x0").valid);
        CHECK(!TraceValueOrigin(g, Arch::X64, 2, "xmm0").valid);
        CHECK(!TraceValueOrigin(g, Arch::X64, 999, "eax").valid);
        g.complete = false; g.incompleteReason = "Missing tail";
        r = TraceValueOrigin(g, Arch::X64, 2, "ecx");
        CHECK(!r.complete && boundary(r, ValueOriginBoundaryKind::IncompleteGraph));
        r = TraceValueOrigin(g, Arch::X64, 2, "ecx", {1, 2048, {}});
        CHECK(!r.complete && boundary(r, ValueOriginBoundaryKind::Limit));
        r = TraceValueOrigin(g, Arch::X64, 2, "ecx", {8192, 0, {}});
        CHECK(!r.complete && boundary(r, ValueOriginBoundaryKind::Limit));
        r = TraceValueOrigin(g, Arch::X64, 2, "ecx", {8192, 2048, [] { return true; }});
        CHECK(r.cancelled && !r.valid && r.sources.empty());
    }
    std::printf("value_origin_test: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
