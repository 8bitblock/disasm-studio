#include "Core/BinaryFile.h"
#include "Core/SemanticDiffBinary.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>

using namespace ds;

namespace {

class TinyDecoder : public IDisassembler {
public:
    Engine engine() const override { return Engine::Capstone; }
    const char* engineName() const override { return "semantic-diff-test"; }

    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t virtualAddress,
                                         size_t maxInstructions) override {
        std::vector<Instruction> result;
        size_t offset = 0;
        while (offset < size && (!maxInstructions || result.size() < maxInstructions)) {
            Instruction instruction;
            if (!decodeOne(data + offset, size - offset, virtualAddress + offset, instruction)) break;
            result.push_back(instruction);
            offset += instruction.length;
        }
        return result;
    }

    bool decodeOne(const uint8_t* data, size_t size, uint64_t virtualAddress,
                   Instruction& output) override {
        if (!data || !size) return false;
        output = {};
        output.address = virtualAddress;
        output.length = 1;
        if (*data == 0xC3) {
            output.mnemonic = "ret";
            output.isBranch = true;
            output.isRet = true;
            output.flow.kind = FlowKind::Return;
        } else if (*data == 0xE9) {
            output.mnemonic = "jmp";
            output.isBranch = true;
            output.branchTarget = virtualAddress + 0x20;
            output.branchTargetValid = true;
            output.flow.kind = FlowKind::UnconditionalBranch;
            output.flow.directTarget = output.branchTarget;
            output.flow.directTargetValid = true;
        } else {
            output.mnemonic = "nop";
        }
        return true;
    }
};

class FailedDecoder final : public TinyDecoder {
public:
    bool ready() const override { return false; }
    std::string_view errorMessage() const override { return "fixture decoder refused config"; }
};

template <typename T>
void put(std::vector<uint8_t>& bytes, size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

std::filesystem::path writeRvcElf() {
    std::vector<uint8_t> bytes(0x100, 0);
    std::memcpy(bytes.data(), "\x7f" "ELF", 4);
    bytes[4] = 1; bytes[5] = 1; bytes[6] = 1;
    put<uint16_t>(bytes, 16, 2);      // ET_EXEC
    put<uint16_t>(bytes, 18, 0xF3);   // EM_RISCV
    put<uint32_t>(bytes, 20, 1);
    put<uint32_t>(bytes, 24, 0x10080);
    put<uint32_t>(bytes, 28, 52);
    put<uint32_t>(bytes, 36, 1);      // EF_RISCV_RVC
    put<uint16_t>(bytes, 40, 52);
    put<uint16_t>(bytes, 42, 32);
    put<uint16_t>(bytes, 44, 1);
    put<uint32_t>(bytes, 52, 1);      // PT_LOAD
    put<uint32_t>(bytes, 56, 0);
    put<uint32_t>(bytes, 60, 0x10000);
    put<uint32_t>(bytes, 64, 0x10000);
    put<uint32_t>(bytes, 68, static_cast<uint32_t>(bytes.size()));
    put<uint32_t>(bytes, 72, static_cast<uint32_t>(bytes.size()));
    put<uint32_t>(bytes, 76, 5);      // PF_R | PF_X
    put<uint32_t>(bytes, 80, 0x1000);
    bytes[0x80] = 0xC3;
    const auto path = std::filesystem::temp_directory_path() /
                      "ds_semantic_diff_rvc.elf";
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    return path;
}

} // namespace

int main() {
    std::vector<uint8_t> bytes(64, 0x90);
    bytes[1] = 0xC3;
    BinaryFile binary;
    assert(binary.loadFromMemory(std::move(bytes), 0x4000, "fixture.raw"));

    DiscoveredFunction discovered;
    discovered.address = 0x4000;
    discovered.size = 2;
    discovered.name = "entry";
    discovered.isExport = true;
    discovered.chunks.push_back({0x4000, 2});
    std::vector<DiscoveredFunction> functions{discovered};

    SemanticImageBuildResult built = BuildSemanticImage(
        binary, Arch::X64,
        [](Arch) -> std::unique_ptr<IDisassembler> { return std::make_unique<TinyDecoder>(); },
        {}, {}, &functions);
    assert(built.complete && !built.cancelled && built.error.empty());
    assert(built.image.contentIdentity == binary.contentHash());
    assert(built.image.functions.size() == 1);
    const SemanticFunction& function = built.image.functions.front();
    assert(function.address == 0x4000 && function.authoritativeName);
    assert(function.instructions.size() == 2);
    assert(function.instructions[1].flow.kind == FlowKind::Return);
    assert(!function.blocks.empty());

    // Noncontiguous chunks are one function CFG: an explicit branch from the
    // first chunk must retain its edge into the second chunk.
    std::vector<uint8_t> chunkBytes(64, 0x90);
    chunkBytes[0x10] = 0xE9;
    chunkBytes[0x30] = 0xC3;
    BinaryFile chunkBinary;
    assert(chunkBinary.loadFromMemory(std::move(chunkBytes), 0x4000, "chunks.raw"));
    DiscoveredFunction chunkFunction;
    chunkFunction.address = 0x4010;
    chunkFunction.size = 2;
    chunkFunction.name = "chunked";
    chunkFunction.chunks = {{0x4010, 1}, {0x4030, 1}};
    std::vector<DiscoveredFunction> chunkFunctions{chunkFunction};
    SemanticImageBuildResult chunkBuild = BuildSemanticImage(
        chunkBinary, Arch::X64,
        [](Arch) -> std::unique_ptr<IDisassembler> { return std::make_unique<TinyDecoder>(); },
        {}, {}, &chunkFunctions);
    assert(chunkBuild.complete && !chunkBuild.truncated);
    assert(chunkBuild.image.functions.size() == 1);
    const SemanticFunction& chunked = chunkBuild.image.functions.front();
    auto sourceBlock = std::find_if(chunked.blocks.begin(), chunked.blocks.end(),
        [](const SemanticBasicBlock& block) { return block.address == 0x4010; });
    assert(sourceBlock != chunked.blocks.end());
    assert(std::find(sourceBlock->successors.begin(), sourceBlock->successors.end(), 0x4030) !=
           sourceBlock->successors.end());

    DecoderConfig configured;
    configured.engine = Engine::Capstone;
    configured.arch = Arch::PPC;
    configured.byteOrder = ByteOrder::Big;
    configured.features.riscvCompressed = false;
    DecoderConfig observed;
    SemanticImageBuildResult configuredBuild = BuildSemanticImage(
        binary, configured,
        [&](const DecoderConfig& request) -> std::unique_ptr<IDisassembler> {
            observed = request;
            return std::make_unique<TinyDecoder>();
        }, {}, {}, &functions);
    assert(configuredBuild.complete && configuredBuild.image.arch == Arch::PPC);
    assert(observed == configured);

    // Semantic/Binary Diff workers must use structured loader metadata, not a
    // stale UI/default architecture or feature set supplied by their caller.
    const std::filesystem::path rvcPath = writeRvcElf();
    BinaryFile rvcBinary;
    assert(rvcBinary.load(rvcPath.string()));
    std::error_code removeError;
    std::filesystem::remove(rvcPath, removeError);
    DiscoveredFunction rvcFunction;
    rvcFunction.address = 0x10080;
    rvcFunction.size = 1;
    rvcFunction.chunks.push_back({0x10080, 1});
    std::vector<DiscoveredFunction> rvcFunctions{rvcFunction};
    DecoderConfig staleStructured;
    staleStructured.engine = Engine::Capstone;
    staleStructured.arch = Arch::X64;
    staleStructured.byteOrder = ByteOrder::Big;
    DecoderConfig observedStructured;
    const SemanticImageBuildResult rvcBuild = BuildSemanticImage(
        rvcBinary, staleStructured,
        [&](const DecoderConfig& request) -> std::unique_ptr<IDisassembler> {
            observedStructured = request;
            return std::make_unique<TinyDecoder>();
        }, {}, {}, &rvcFunctions);
    assert(rvcBuild.complete && rvcBuild.image.arch == Arch::RISCV32);
    assert(observedStructured.arch == Arch::RISCV32);
    assert(observedStructured.byteOrder == ByteOrder::Little);
    assert(observedStructured.features.riscvCompressed);

    SemanticImageBuildResult failed = BuildSemanticImage(
        binary, configured,
        [](const DecoderConfig&) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<FailedDecoder>();
        }, {}, {}, &functions);
    assert(!failed.complete && !failed.error.empty());
    assert(failed.error.find("fixture decoder refused config") != std::string::npos);

    SemanticImageBuildResult cancelled = BuildSemanticImage(
        binary, Arch::X64,
        [](Arch) -> std::unique_ptr<IDisassembler> { return std::make_unique<TinyDecoder>(); },
        {}, [] { return true; }, &functions);
    assert(cancelled.cancelled && !cancelled.complete);

    std::cout << "semantic_diff_binary_test: OK\n";
    return 0;
}
