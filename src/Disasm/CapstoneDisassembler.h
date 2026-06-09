#pragma once
#include "IDisassembler.h"

namespace ds {

// Capstone-backed implementation. Multi-architecture (x86/x64/ARM/ARM64).
class CapstoneDisassembler final : public IDisassembler {
public:
    explicit CapstoneDisassembler(Arch arch = Arch::X64);
    ~CapstoneDisassembler() override;

    Engine      engine()     const override { return Engine::Capstone; }
    const char* engineName() const override { return "Capstone"; }

    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t virtualAddress,
                                         size_t maxInstructions = 0) override;
    bool decodeOne(const uint8_t* data, size_t size,
                   uint64_t virtualAddress, Instruction& out) override;

private:
    bool open();
    void close();

    Arch      arch_;
    uintptr_t handle_   = 0;       // csh
    void*     scratch_  = nullptr; // reusable cs_insn for cs_disasm_iter
    bool      ok_       = false;
};

} // namespace ds
