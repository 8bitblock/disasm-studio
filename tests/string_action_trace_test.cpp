#include "Core/StringActionTrace.h"
#include "Core/BinaryFile.h"
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <unordered_map>

using namespace ds;
static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL %d: %s\n", __LINE__, #x); ++failures; } } while (0)

static TypedOperand reg(const char* name, OperandAccess access, uint16_t width = 32) {
    TypedOperand operand; operand.kind = OperandKind::Register;
    operand.registerName = name; operand.access = access; operand.widthBits = width; return operand;
}
static TypedOperand memory(const char* base, OperandAccess access, uint16_t width = 32) {
    TypedOperand operand; operand.kind = OperandKind::Memory;
    operand.baseRegister = base; operand.access = access; operand.widthBits = width;
    operand.displacement = 0x17c; operand.displacementValid = true; return operand;
}
static TypedOperand immediate(uint64_t value) {
    TypedOperand operand; operand.kind = OperandKind::Immediate;
    operand.immediate = value; operand.access = OperandAccess::Read; operand.widthBits = 32; return operand;
}
static Instruction op(uint64_t va, const char* mnemonic, std::vector<TypedOperand> operands = {}) {
    Instruction in; in.address = va; in.length = 1; in.mnemonic = mnemonic;
    in.typedOperands = std::move(operands); return in;
}
static Instruction add(uint64_t va, const char* base = "rbx") {
    auto in = op(va, "add", {memory(base, OperandAccess::ReadWrite), immediate(1)});
    in.operands = "dword ptr [rbx+0x17c], 1"; return in;
}
static Instruction str(uint64_t va, uint64_t address = 0x9000) {
    auto data = memory("", OperandAccess::Read, 64); data.displacement = static_cast<int64_t>(address);
    auto in = op(va, "lea", {reg("rcx", OperandAccess::Write, 64), data}); return in;
}
static Instruction call(uint64_t va, uint64_t target) {
    auto in = op(va, "call"); in.flow.kind = FlowKind::DirectCall;
    in.flow.directTargetValid = true; in.flow.directTarget = target; return in;
}
static Instruction ret(uint64_t va) {
    auto in = op(va, "ret"); in.flow.kind = FlowKind::Return; return in;
}
static BasicBlock block(std::vector<Instruction> instructions, std::vector<size_t> successors = {}) {
    BasicBlock out; out.start = instructions.front().address;
    out.end = instructions.back().address + instructions.back().length;
    out.insns = std::move(instructions); out.succ = std::move(successors); return out;
}
static StringActionTraceFunction function(uint64_t va, std::vector<BasicBlock> blocks) {
    StringActionTraceFunction out; out.graph.funcStart = va; out.graph.blocks = std::move(blocks); return out;
}
static const StringActionTraceCandidate* at(const StringActionTraceResult& result, uint64_t va) {
    for (const auto& candidate : result.candidates) if (candidate.instructionVA == va) return &candidate;
    return nullptr;
}

static void workerAdapter() {
    struct Decoder final : IDisassembler {
        std::unordered_map<uint64_t, Instruction> script;
        Engine engine() const override { return Engine::Zydis; }
        const char* engineName() const override { return "script"; }
        bool decodeOne(const uint8_t*, size_t size, uint64_t va, Instruction& out) override {
            const auto found = script.find(va);
            if (!size || found == script.end()) return false;
            out = found->second; return true;
        }
        std::vector<Instruction> disassemble(const uint8_t* bytes, size_t size, uint64_t va, size_t cap) override {
            std::vector<Instruction> out;
            for (size_t offset = 0; offset < size && (!cap || out.size() < cap);) {
                Instruction in;
                if (!decodeOne(bytes + offset, size - offset, va + offset, in)) break;
                offset += in.length; out.push_back(std::move(in));
            }
            return out;
        }
    } decoder;
    const auto serial = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto path = std::filesystem::temp_directory_path() /
        ("ds_string_action_" + std::to_string(serial) + ".bin");
    { std::ofstream file(path, std::ios::binary); std::string bytes(0x300, '\x90'); file.write(bytes.data(), bytes.size()); }
    BinaryFile bin;
    CHECK(bin.loadRaw(path.string(), 0x1000));
    decoder.script = {{0x1000, str(0x1000, 0x1200)}, {0x1001, call(0x1001, 0x1100)},
                      {0x1002, add(0x1002)}, {0x1003, ret(0x1003)}, {0x1100, ret(0x1100)}};
    StringActionTraceRequest request;
    request.stringVA = 0x1200; request.stringText = "points added!";
    request.functions.push_back({0x1000, 4, "sub_1000", false});
    request.functions.push_back({0x1100, 1, "exit_worker", false});
    auto xrefs = std::make_shared<XrefIndex>();
    xrefs->toTarget[0x1200] = {0x1000}; xrefs->toTarget[0x1100] = {0x1001}; request.xrefs = xrefs;
    auto result = BuildStringActionTrace(bin, decoder, Arch::X64, request, {});
    CHECK(result.valid && at(result, 0x1002));
    request.functions[1].noreturn = true;
    result = BuildStringActionTrace(bin, decoder, Arch::X64, request, {});
    CHECK(result.valid && result.candidates.empty());
    request.functions[1].noreturn = false;
    xrefs->complete = false;
    result = BuildStringActionTrace(bin, decoder, Arch::X64, request, {});
    CHECK(result.valid && !result.complete && !result.limitations.empty());
    decoder.script[0x1000] = str(0x1000, 0x1208); // stale index must be rechecked
    result = BuildStringActionTrace(bin, decoder, Arch::X64, request, {});
    CHECK(!result.valid && result.candidates.empty());
    request.cancellation = std::make_shared<std::atomic<bool>>(true);
    result = BuildStringActionTrace(bin, decoder, Arch::X64, request, {});
    CHECK(result.cancelled && result.candidates.empty());
    std::error_code ignored; std::filesystem::remove(path, ignored);
}

int main() {
    auto local = function(0x1000, {block({add(0x1000), str(0x1001), ret(0x1002)})});
    auto result = TraceStringActions({local}, Arch::X64, 0x9000, "added!");
    CHECK(result.valid && result.complete && !result.cancelled);
    CHECK(result.candidates.size() == 1);
    CHECK(at(result, 0x1000) && at(result, 0x1000)->suggestedName == "add_value_candidate");
    CHECK(at(result, 0x1000) && at(result, 0x1000)->stringRefVA == 0x1001);
    CHECK(at(result, 0x1000) && at(result, 0x1000)->path.size() == 3);
    result = TraceStringActions({local}, Arch::X64, 0x9000, "5 points added!");
    CHECK(at(result, 0x1000) && at(result, 0x1000)->suggestedName == "add_points_candidate");
    for (const char* misleading : {"Point was not added!", "Failed to add points", "address", "addedness", "points", "points removed"}) {
        result = TraceStringActions({local}, Arch::X64, 0x9000, misleading);
        CHECK(at(result, 0x1000) && at(result, 0x1000)->suggestedName.empty());
    }
    auto decreasing = add(0x1000);
    decreasing.typedOperands[1].immediate = 0xff;
    decreasing.typedOperands[1].widthBits = 8;
    decreasing.typedOperands[1].immediateSigned = true;
    result = TraceStringActions({function(0x1000, {block({decreasing, str(0x1001), ret(0x1002)})})},
                               Arch::X64, 0x9000, "points added!");
    CHECK(at(result, 0x1000) && at(result, 0x1000)->suggestedName.empty());
    CHECK(at(result, 0x1000) && at(result, 0x1000)->action == "subtraction from stored value");
    decreasing.mnemonic = "sub";
    result = TraceStringActions({function(0x1000, {block({decreasing, str(0x1001), ret(0x1002)})})},
                               Arch::X64, 0x9000, "points added!");
    CHECK(at(result, 0x1000) && at(result, 0x1000)->suggestedName == "add_points_candidate");

    // A register arithmetic result is linked to its exact eventual write.
    auto arithmetic = op(0x2001, "add", {reg("eax", OperandAccess::ReadWrite), reg("ecx", OperandAccess::Read)});
    auto load = op(0x2000, "mov", {reg("eax", OperandAccess::Write), memory("rbx", OperandAccess::Read)});
    auto store = op(0x2002, "mov", {memory("rbx", OperandAccess::Write), reg("eax", OperandAccess::Read)});
    auto lineage = function(0x2000, {block({load, arithmetic, store, str(0x2003), ret(0x2004)})});
    result = TraceStringActions({lineage}, Arch::X64, 0x9000, "score increased");
    CHECK(at(result, 0x2002) && at(result, 0x2002)->producerVAValid && at(result, 0x2002)->producerVA == 0x2001);
    CHECK(at(result, 0x2002) && at(result, 0x2002)->suggestedName == "add_score_candidate");
    auto overwrite = op(0x2002, "xor", {reg("eax", OperandAccess::ReadWrite), reg("eax", OperandAccess::Read)});
    store.address = 0x2003;
    auto clobbered = function(0x2000, {block({load, arithmetic, overwrite, store, str(0x2004), ret(0x2005)})});
    result = TraceStringActions({clobbered}, Arch::X64, 0x9000, "added!");
    CHECK(at(result, 0x2003) && !at(result, 0x2003)->producerVAValid && at(result, 0x2003)->suggestedName.empty());
    auto narrowStore = op(0x2002, "mov", {memory("rbx", OperandAccess::Write, 8), reg("al", OperandAccess::Read, 8)});
    result = TraceStringActions({function(0x2000, {block({load, arithmetic, narrowStore, str(0x2003), ret(0x2004)})})},
                               Arch::X64, 0x9000, "added!");
    CHECK(at(result, 0x2002) && !at(result, 0x2002)->producerVAValid);

    // Mutually exclusive blocks are not related just because their addresses
    // or their common successor happen to be close.
    auto branch = op(0x3000, "jz"); branch.flow.kind = FlowKind::ConditionalBranch;
    auto jump = op(0x3011, "jmp"); jump.flow.kind = FlowKind::UnconditionalBranch;
    auto branchDecoy = function(0x3000, {
        block({branch}, {1, 2}), block({str(0x3010), jump}, {3}),
        block({add(0x3020)}, {3}), block({ret(0x3030)})});
    result = TraceStringActions({branchDecoy}, Arch::X64, 0x9000, "points added!");
    CHECK(result.valid && result.candidates.empty());
    auto unrelated = function(0x4000, {block({add(0x4000), ret(0x4001)})});
    result = TraceStringActions({function(0x5000, {block({str(0x5000), ret(0x5001)})}), unrelated},
                               Arch::X64, 0x9000, "added!");
    CHECK(result.valid && result.candidates.empty());

    // Actual direct calls provide navigable evidence in both directions.
    auto caller = function(0x5000, {block({call(0x5000, 0x4000), str(0x5001), ret(0x5002)})});
    result = TraceStringActions({caller, unrelated}, Arch::X64, 0x9000, "added!");
    CHECK(at(result, 0x4000) && at(result, 0x4000)->path.size() >= 5);
    CHECK(at(result, 0x4000) && at(result, 0x4000)->confidence < 0.78f);
    auto logger = function(0x6000, {block({str(0x6000), ret(0x6001)})});
    auto points = function(0x7000, {block({add(0x7000), call(0x7001, 0x6000), ret(0x7002)})});
    result = TraceStringActions({logger, points}, Arch::X64, 0x9000, "points added!");
    CHECK(at(result, 0x7000) && at(result, 0x7000)->stringRefVA == 0x6000);
    points.graph.blocks[0].insns[1].flow.kind = FlowKind::IndirectCall;
    result = TraceStringActions({logger, points}, Arch::X64, 0x9000, "added!");
    CHECK(result.candidates.empty()); // stale direct target cannot bless an indirect call

    // Stack bookkeeping, untyped guesses and unexecuted decoy blocks do not
    // acquire semantic value-change names.
    auto untyped = op(0x8000, "add"); untyped.operands = "[rbx], 1";
    result = TraceStringActions({function(0x8000, {block({untyped, add(0x8001, "rsp"), str(0x8002), ret(0x8003)})})},
                               Arch::X64, 0x9000, "added!");
    CHECK(result.candidates.empty());
    result = TraceStringActions({function(0x8000, {block({ret(0x8000)}), block({str(0x8010), add(0x8011)})})},
                               Arch::X64, 0x9000, "added!");
    CHECK(!result.valid && result.candidates.empty());
    result = TraceStringActions({local}, Arch::ARM64, 0x9000, "added!");
    CHECK(!result.valid && result.candidates.empty());
    result = TraceStringActions({function(0, {block({str(0, 0), add(1), ret(2)})})}, Arch::X64, 0, "added!");
    CHECK(result.valid && at(result, 1) && at(result, 1)->stringRefVA == 0 && at(result, 1)->functionVA == 0);

    StringActionTraceLimits limits;
    limits.cancelled = [] { return true; };
    result = TraceStringActions({local}, Arch::X64, 0x9000, "added!", limits);
    CHECK(result.cancelled && result.candidates.empty());
    size_t polls = 0;
    limits.cancelled = [&] { return ++polls > 5; };
    result = TraceStringActions({caller, unrelated}, Arch::X64, 0x9000, "added!", limits);
    CHECK(result.cancelled && result.candidates.empty());
    limits = {}; limits.maxCandidates = 1;
    result = TraceStringActions({function(0x1000, {block({add(0x1000), add(0x1001), str(0x1002), ret(0x1003)})})},
                               Arch::X64, 0x9000, "added!", limits);
    CHECK(result.candidates.size() == 1 && !result.complete && !result.limitations.empty());
    limits = {}; limits.maxInstructionDistance = 1;
    result = TraceStringActions({function(0x1000, {block({add(0x1000), op(0x1001, "nop"), str(0x1002), ret(0x1003)})})},
                               Arch::X64, 0x9000, "added!", limits);
    CHECK(result.candidates.empty() && !result.complete);
    limits = {}; limits.maxInputFunctions = 0;
    result = TraceStringActions({local}, Arch::X64, 0x9000, "added!", limits);
    CHECK(!result.valid && result.candidates.empty());
    local.graph.complete = false;
    result = TraceStringActions({local}, Arch::X64, 0x9000, "added!");
    CHECK(result.valid && !result.complete && at(result, 0x1000));

    workerAdapter();
    std::printf("string_action_trace_test: %d failures\n", failures);
    return failures ? 1 : 0;
}
