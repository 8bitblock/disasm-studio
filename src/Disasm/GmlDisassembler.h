#pragma once
#include "IDisassembler.h"
#include "../Core/GameMakerArchive.h"
#include <memory>

namespace ds {
class GmlDisassembler final : public IDisassembler {
public:
    GmlDisassembler() = default;
    explicit GmlDisassembler(const DecoderConfig& config);
    void attachArchive(std::shared_ptr<const GameMakerArchive> archive);
    Engine engine() const override { return Engine::Capstone; }
    const char* engineName() const override { return "GameMaker GML bytecode"; }
    bool ready() const override;
    std::string_view errorMessage() const override;
    uint32_t invalidDecodeWidth() const override { return 4; }
    uint32_t instructionAlignment() const override { return 4; }
    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
        uint64_t virtualAddress, size_t maxInstructions = 0) override;
    bool decodeOne(const uint8_t* data, size_t size,
        uint64_t virtualAddress, Instruction& out) override;
private:
    std::shared_ptr<const GameMakerArchive> archive_;
    std::string error_;
};
void AttachGameMakerArchive(IDisassembler& dis, std::shared_ptr<const GameMakerArchive> archive);
} // namespace ds
