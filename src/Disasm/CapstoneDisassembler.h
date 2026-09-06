#pragma once
#include "IDisassembler.h"

namespace ds {

// Capstone-backed implementation. Multi-architecture (x86-16/x86/x64 and non-x86 targets).
class CapstoneDisassembler final : public IDisassembler {
public:
    explicit CapstoneDisassembler(Arch arch = Arch::X64);
    explicit CapstoneDisassembler(const DecoderConfig& config);
    ~CapstoneDisassembler() override;

    Engine      engine()     const override { return Engine::Capstone; }
    const char* engineName() const override { return "Capstone"; }
    bool ready() const override { return ok_; }
    std::string_view errorMessage() const override { return error_; }
    uint32_t invalidDecodeWidth() const override { return ArchInvalidDecodeWidth(config_); }
    uint32_t instructionAlignment() const override { return ArchInstructionAlignment(config_); }

    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t virtualAddress,
                                         size_t maxInstructions = 0) override;
    bool decodeOne(const uint8_t* data, size_t size,
                   uint64_t virtualAddress, Instruction& out) override;

private:
    bool open();
    void close();

    DecoderConfig config_;
    Arch      arch_;
    uintptr_t handle_   = 0;       // csh
    void*     scratch_  = nullptr; // reusable cs_insn for cs_disasm_iter
    bool      ok_       = false;
    std::string error_;
};

} // namespace ds
