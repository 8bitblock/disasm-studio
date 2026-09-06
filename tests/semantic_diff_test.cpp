#include "Core/SemanticDiff.h"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <iostream>
#include <memory>
#include <thread>

using namespace ds;

namespace {

SemanticInstruction op(uint64_t address, const char* mnemonic,
                       FlowKind flow = FlowKind::None) {
    SemanticInstruction instruction;
    instruction.address = address;
    instruction.length = 1;
    instruction.mnemonic = mnemonic;
    instruction.display = mnemonic;
    instruction.flow.kind = flow;
    return instruction;
}

SemanticInstruction constantOp(uint64_t address, uint64_t value) {
    SemanticInstruction instruction = op(address, "mov");
    SemanticOperand destination;
    destination.kind = OperandKind::Register;
    destination.access = OperandAccess::Write;
    destination.widthBits = 32;
    destination.registerName = "eax";
    SemanticOperand immediate;
    immediate.kind = OperandKind::Immediate;
    immediate.access = OperandAccess::Read;
    immediate.widthBits = 32;
    immediate.immediate = value;
    instruction.operands = {destination, immediate};
    return instruction;
}

SemanticInstruction relocatedLoad(uint64_t address, uint64_t absoluteAddress) {
    SemanticInstruction instruction = op(address, "mov");
    SemanticOperand destination;
    destination.kind = OperandKind::Register;
    destination.access = OperandAccess::Write;
    destination.widthBits = 64;
    destination.registerName = "rax";
    SemanticOperand source;
    source.kind = OperandKind::Memory;
    source.access = OperandAccess::Read;
    source.widthBits = 64;
    source.displacementValid = true;
    source.displacement = static_cast<int64_t>(absoluteAddress);
    source.valueIsRelocation = true;
    instruction.operands = {destination, source};
    return instruction;
}

SemanticInstruction call(uint64_t address, uint64_t target) {
    SemanticInstruction instruction = op(address, "call", FlowKind::DirectCall);
    instruction.flow.directTargetValid = true;
    instruction.flow.directTarget = target;
    SemanticOperand immediate;
    immediate.kind = OperandKind::Immediate;
    immediate.access = OperandAccess::Read;
    immediate.widthBits = 32;
    immediate.immediate = target;
    immediate.valueIsRelocation = true;
    instruction.operands.push_back(immediate);
    return instruction;
}

SemanticFunction linear(uint64_t address, std::string name,
                        std::vector<SemanticInstruction> instructions,
                        bool authoritative = false) {
    SemanticFunction function;
    function.address = address;
    function.size = instructions.size();
    function.name = std::move(name);
    function.authoritativeName = authoritative;
    function.nameTransferable = authoritative;
    function.instructions = std::move(instructions);
    SemanticBasicBlock block;
    block.address = address;
    for (uint32_t i = 0; i < function.instructions.size(); ++i)
        block.instructionIndices.push_back(i);
    function.blocks.push_back(std::move(block));
    return function;
}

const SemanticFunctionMatch* matchAt(const SemanticDiffResult& result, uint64_t leftAddress) {
    for (const SemanticFunctionMatch& match : result.matched)
        if (match.leftAddress == leftAddress) return &match;
    return nullptr;
}

void relocatedSectionsAreSemanticEquals() {
    SemanticImage left, right;
    left.arch = right.arch = Arch::X64;
    left.functions.push_back(linear(0x1000, "",
        {relocatedLoad(0x1000, 0x4000), call(0x1001, 0x2000),
         op(0x1002, "ret", FlowKind::Return)}));
    left.functions.back().callTargets = {0x2000};
    left.functions.push_back(linear(0x2000, "",
        {op(0x2000, "xor"), op(0x2001, "ret", FlowKind::Return)}));

    right.functions.push_back(linear(0x71000, "",
        {relocatedLoad(0x71000, 0x74000), call(0x71001, 0x72000),
         op(0x71002, "ret", FlowKind::Return)}));
    right.functions.back().callTargets = {0x72000};
    right.functions.push_back(linear(0x72000, "",
        {op(0x72000, "xor"), op(0x72001, "ret", FlowKind::Return)}));

    SemanticDiffResult result = ComputeSemanticDiff(left, right);
    assert(result.complete && !result.cancelled && result.error.empty());
    assert(result.matched.size() == 2 && result.added.empty() && result.removed.empty());
    const SemanticFunctionMatch* main = matchAt(result, 0x1000);
    assert(main && main->rightAddress == 0x71000);
    assert(main->basis == SemanticMatchBasis::SemanticHash);
    assert(main->leftSemanticHash == main->rightSemanticHash);
    assert(main->hunks.empty());
}

void renamedFunctionsYieldOnlyExplicitProposals() {
    SemanticImage left, right;
    left.arch = right.arch = Arch::X64;
    left.functions.push_back(linear(0x1000, "parse_packet",
        {op(0x1000, "push"), op(0x1001, "ret", FlowKind::Return)}));
    right.functions.push_back(linear(0x5000, "sub_5000",
        {op(0x5000, "push"), op(0x5001, "ret", FlowKind::Return)}));
    left.functions[0].nameTransferable = true;
    left.functions[0].prototype = "bool parse_packet(const void*)";
    left.functions[0].comments.push_back({0, "validated header"});
    left.functions[0].bookmarkInstructions.push_back(1);

    const std::string originalRightName = right.functions[0].name;
    SemanticDiffResult result = ComputeSemanticDiff(left, right);
    assert(result.complete && result.matched.size() == 1);
    assert(right.functions[0].name == originalRightName); // no implicit mutation
    assert(std::any_of(result.transferProposals.begin(), result.transferProposals.end(),
        [](const MetadataTransferProposal& proposal) {
            return proposal.kind == MetadataTransferKind::Name &&
                   proposal.direction == MetadataTransferDirection::LeftToRight &&
                   proposal.value == "parse_packet" && proposal.requiresExplicitSelection;
        }));
    assert(std::any_of(result.transferProposals.begin(), result.transferProposals.end(),
        [](const MetadataTransferProposal& proposal) {
            return proposal.kind == MetadataTransferKind::Comment &&
                   proposal.targetInstructionValid && proposal.targetInstructionIndex == 0;
        }));
    assert(std::any_of(result.transferProposals.begin(), result.transferProposals.end(),
        [](const MetadataTransferProposal& proposal) {
            return proposal.kind == MetadataTransferKind::Bookmark &&
                   proposal.targetInstructionValid && proposal.targetInstructionIndex == 1;
        }));
}

void insertedFunctionIsReported() {
    SemanticImage left, right;
    left.arch = right.arch = Arch::X64;
    left.functions.push_back(linear(0x1000, "", {constantOp(0x1000, 7)}));
    right.functions.push_back(linear(0x9000, "", {constantOp(0x9000, 7)}));
    right.functions.push_back(linear(0xA000, "new_worker",
        {op(0xA000, "xor"), op(0xA001, "ret", FlowKind::Return)}));
    SemanticDiffResult result = ComputeSemanticDiff(left, right);
    assert(result.complete && result.matched.size() == 1);
    assert(result.added.size() == 1 && result.added[0].address == 0xA000);
    assert(result.removed.empty());
}

void reorderedBlocksStillMatch() {
    SemanticImage left, right;
    left.arch = right.arch = Arch::X64;

    SemanticFunction lf;
    lf.address = 0x1000;
    SemanticInstruction jumpLeft = op(0x1001, "jmp", FlowKind::UnconditionalBranch);
    jumpLeft.flow.directTargetValid = true;
    jumpLeft.flow.directTarget = 0x1010;
    lf.instructions = {op(0x1000, "mov"), jumpLeft,
                       op(0x1010, "ret", FlowKind::Return)};
    lf.blocks = {{0x1000, {0, 1}, {0x1010}}, {0x1010, {2}, {}}};

    SemanticFunction rf;
    rf.address = 0x8000;
    SemanticInstruction jumpRight = op(0x8001, "jmp", FlowKind::UnconditionalBranch);
    jumpRight.flow.directTargetValid = true;
    jumpRight.flow.directTarget = 0x8010;
    // Storage and block vectors are both reordered; block-local sequences and
    // topology remain equivalent.
    rf.instructions = {op(0x8010, "ret", FlowKind::Return),
                       op(0x8000, "mov"), jumpRight};
    rf.blocks = {{0x8010, {0}, {}}, {0x8000, {1, 2}, {0x8010}}};

    left.functions.push_back(std::move(lf));
    right.functions.push_back(std::move(rf));
    SemanticDiffResult result = ComputeSemanticDiff(left, right);
    assert(result.complete && result.matched.size() == 1);
    const SemanticFunctionMatch& match = result.matched.front();
    assert(match.basis == SemanticMatchBasis::SemanticHash);
    assert(match.leftSemanticHash == match.rightSemanticHash);
    assert(!match.hunks.empty()); // instruction presentation order changed
}

void constantOnlyChangeFallsBackToCfgAndProducesAHunk() {
    SemanticImage left, right;
    left.arch = right.arch = Arch::X64;
    left.functions.push_back(linear(0x1000, "",
        {constantOp(0x1000, 1), op(0x1001, "ret", FlowKind::Return)}));
    right.functions.push_back(linear(0x2000, "",
        {constantOp(0x2000, 2), op(0x2001, "ret", FlowKind::Return)}));
    SemanticDiffResult result = ComputeSemanticDiff(left, right);
    assert(result.complete && result.matched.size() == 1);
    const SemanticFunctionMatch& match = result.matched.front();
    assert(match.basis == SemanticMatchBasis::CfgStructure);
    assert(match.leftSemanticHash != match.rightSemanticHash);
    assert(match.leftCfgHash == match.rightCfgHash);
    assert(match.hunks.size() == 1);
    assert(match.hunks[0].kind == InstructionEditKind::Replace);
    assert(match.hunks[0].leftBegin == 0 && match.hunks[0].rightBegin == 0);
}

void semanticPrefixesArePartOfInstructionIdentity() {
    Instruction prefixed;
    prefixed.address = 0x1000;
    prefixed.length = 2;
    prefixed.mnemonic = "movsb";
    prefixed.prefixes = {InstructionPrefix::Rep};
    SemanticInstruction semanticPrefixed = MakeSemanticInstruction(prefixed);
    assert(semanticPrefixed.prefixes == prefixed.prefixes);
    assert(semanticPrefixed.display == "rep movsb");

    Instruction plain = prefixed;
    plain.address = 0x2000;
    plain.prefixes.clear();

    SemanticImage left, right;
    left.arch = right.arch = Arch::X64;
    left.functions.push_back(linear(0x1000, "copy_bytes",
        {semanticPrefixed, op(0x1002, "ret", FlowKind::Return)}, true));
    right.functions.push_back(linear(0x2000, "copy_bytes",
        {MakeSemanticInstruction(plain), op(0x2002, "ret", FlowKind::Return)}, true));

    SemanticDiffResult result = ComputeSemanticDiff(left, right);
    assert(result.complete && result.matched.size() == 1);
    const SemanticFunctionMatch& match = result.matched.front();
    assert(match.basis == SemanticMatchBasis::AuthoritativeName);
    assert(match.leftSemanticHash != match.rightSemanticHash);
    assert(!match.hunks.empty());
}

void aarch64TestBitImmediateRemainsSemantic() {
    auto makeTbz = [](uint64_t address, uint64_t bit, uint64_t target) {
        Instruction instruction;
        instruction.address = address;
        instruction.length = 4;
        instruction.mnemonic = "tbz";
        instruction.operands = "w0, #" + std::to_string(bit) + ", target";
        instruction.flow.kind = FlowKind::ConditionalBranch;
        instruction.flow.directTargetValid = true;
        instruction.flow.directTarget = target;

        TypedOperand testedRegister;
        testedRegister.kind = OperandKind::Register;
        testedRegister.access = OperandAccess::Read;
        testedRegister.widthBits = 32;
        testedRegister.registerName = "w0";
        TypedOperand bitNumber;
        bitNumber.kind = OperandKind::Immediate;
        bitNumber.access = OperandAccess::Read;
        bitNumber.widthBits = 8;
        bitNumber.immediate = bit;
        TypedOperand branchTarget;
        branchTarget.kind = OperandKind::Immediate;
        branchTarget.access = OperandAccess::Read;
        branchTarget.widthBits = 64;
        branchTarget.immediate = target;
        branchTarget.pcRelative = true;
        instruction.typedOperands = {testedRegister, bitNumber, branchTarget};
        return instruction;
    };

    const SemanticInstruction bitFive =
        MakeSemanticInstruction(makeTbz(0x1000, 5, 0x1040));
    const SemanticInstruction bitSix =
        MakeSemanticInstruction(makeTbz(0x8000, 6, 0x8100));
    assert(bitFive.operands.size() == 3);
    assert(!bitFive.operands[1].valueIsRelocation);
    assert(bitFive.operands[2].valueIsRelocation);

    SemanticImage left, right;
    left.arch = right.arch = Arch::ARM64;
    left.functions.push_back(linear(0x1000, "test_bit",
        {bitFive, op(0x1004, "ret", FlowKind::Return)}, true));
    right.functions.push_back(linear(0x8000, "test_bit",
        {bitSix, op(0x8004, "ret", FlowKind::Return)}, true));
    const SemanticDiffResult changedBit = ComputeSemanticDiff(left, right);
    assert(changedBit.complete && changedBit.matched.size() == 1);
    assert(changedBit.matched.front().basis == SemanticMatchBasis::AuthoritativeName);
    assert(changedBit.matched.front().leftSemanticHash !=
           changedBit.matched.front().rightSemanticHash);

    right.functions[0].instructions[0] =
        MakeSemanticInstruction(makeTbz(0x8000, 5, 0x8100));
    const SemanticDiffResult relocatedOnly = ComputeSemanticDiff(left, right);
    assert(relocatedOnly.complete && relocatedOnly.matched.size() == 1);
    assert(relocatedOnly.matched.front().leftSemanticHash ==
           relocatedOnly.matched.front().rightSemanticHash);
}

void ambiguousWrappersUseCallNeighborhoods() {
    SemanticImage left, right;
    left.arch = right.arch = Arch::X64;
    left.functions.push_back(linear(0x1000, "read_file",
        {op(0x1000, "ret", FlowKind::Return)}, true));
    left.functions.push_back(linear(0x1100, "send_packet",
        {op(0x1100, "ret", FlowKind::Return)}, true));
    left.functions.push_back(linear(0x2000, "", {call(0x2000, 0x1000)}));
    left.functions.back().callTargets = {0x1000};
    left.functions.push_back(linear(0x2100, "", {call(0x2100, 0x1100)}));
    left.functions.back().callTargets = {0x1100};

    right.functions.push_back(linear(0x9000, "read_file",
        {op(0x9000, "ret", FlowKind::Return)}, true));
    right.functions.push_back(linear(0x9100, "send_packet",
        {op(0x9100, "ret", FlowKind::Return)}, true));
    // Reverse wrapper storage order to prove address/order is not the tie-break.
    right.functions.push_back(linear(0xA000, "", {call(0xA000, 0x9100)}));
    right.functions.back().callTargets = {0x9100};
    right.functions.push_back(linear(0xA100, "", {call(0xA100, 0x9000)}));
    right.functions.back().callTargets = {0x9000};

    SemanticDiffResult result = ComputeSemanticDiff(left, right);
    assert(result.complete && result.matched.size() == 4);
    const SemanticFunctionMatch* readWrapper = matchAt(result, 0x2000);
    const SemanticFunctionMatch* sendWrapper = matchAt(result, 0x2100);
    assert(readWrapper && readWrapper->rightAddress == 0xA100);
    assert(sendWrapper && sendWrapper->rightAddress == 0xA000);
    assert(readWrapper->basis == SemanticMatchBasis::CallNeighborhood);
    assert(sendWrapper->basis == SemanticMatchBasis::CallNeighborhood);
}

void cancellationBoundsAndWorkerAreExplicit() {
    SemanticImage left, right;
    left.arch = right.arch = Arch::X64;
    left.functions.push_back(linear(1, "a", {op(1, "ret", FlowKind::Return)}));
    left.functions.push_back(linear(2, "b", {op(2, "ret", FlowKind::Return)}));
    right = left;

    SemanticDiffResult cancelled = ComputeSemanticDiff(left, right, {}, [] { return true; });
    assert(cancelled.cancelled && !cancelled.complete && cancelled.matched.empty());

    SemanticDiffLimits oneFunction;
    oneFunction.maxFunctions = 1;
    SemanticDiffResult bounded = ComputeSemanticDiff(left, right, oneFunction);
    assert(bounded.complete && bounded.truncated && bounded.matched.size() == 1);

    SemanticDiffService service;
    const uint64_t requestId = service.request(std::make_shared<SemanticImage>(left),
                                               std::make_shared<SemanticImage>(right));
    assert(requestId != 0);
    SemanticDiffServiceResult asyncResult;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!service.tryTakeResult(asyncResult) && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    assert(asyncResult.requestId == requestId);
    assert(asyncResult.diff.complete);

    const uint64_t supersededId = service.request(std::make_shared<SemanticImage>(left),
                                                  std::make_shared<SemanticImage>(right));
    const uint64_t latestId = service.request(std::make_shared<SemanticImage>(left),
                                              std::make_shared<SemanticImage>(right));
    assert(supersededId && latestId && supersededId != latestId);
    SemanticDiffServiceResult latestResult;
    const auto latestDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!service.tryTakeResult(latestResult) &&
           std::chrono::steady_clock::now() < latestDeadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    assert(latestResult.requestId == latestId); // stale result is never observable
    SemanticDiffServiceStats stats = service.stats();
    assert(stats.requests >= 3);
    assert(stats.requestsCoalesced || stats.resultsDropped);

    service.cancel();
    assert(!service.tryTakeResult(latestResult));
    service.cancelAndWaitIdle();
}

} // namespace

int main() {
    relocatedSectionsAreSemanticEquals();
    renamedFunctionsYieldOnlyExplicitProposals();
    insertedFunctionIsReported();
    reorderedBlocksStillMatch();
    constantOnlyChangeFallsBackToCfgAndProducesAHunk();
    semanticPrefixesArePartOfInstructionIdentity();
    aarch64TestBitImmediateRemainsSemantic();
    ambiguousWrappersUseCallNeighborhoods();
    cancellationBoundsAndWorkerAreExplicit();
    std::cout << "semantic_diff_test: OK\n";
    return 0;
}
