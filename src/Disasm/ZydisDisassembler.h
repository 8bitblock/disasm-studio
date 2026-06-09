#pragma once
#include "IDisassembler.h"

#include <memory>

namespace ds {

// Zydis-backed implementation. Fast, x86/x64 only, header-light.
class ZydisDisassembler final : public IDisassembler {
public:
    explicit ZydisDisassembler(Arch arch = Arch::X64);
    ~ZydisDisassembler() override;

    Engine      engine()     const override { return Engine::Zydis; }
    const char* engineName() const override { return "Zydis"; }

    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t virtualAddress,
                                         size_t maxInstructions = 0) override;
    bool decodeOne(const uint8_t* data, size_t size,
                   uint64_t virtualAddress, Instruction& out) override;

private:
    // The decoder + formatter depend only on the architecture, so they are built
    // once and reused for every instruction (kept opaque to stay header-light).
    struct ZyState;
    Arch                     arch_;
    std::unique_ptr<ZyState> st_;
};

} // namespace ds
