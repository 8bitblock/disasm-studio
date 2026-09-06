#include "DisassemblerFactory.h"
#include "ZydisDisassembler.h"
#include "CapstoneDisassembler.h"
#include "JvmDisassembler.h"
#include "GmlDisassembler.h"

namespace ds {

std::unique_ptr<IDisassembler> MakeDisassembler(const DecoderConfig& config) {
    // Java bytecode has no Zydis/Capstone backend; it always uses the
    // hand-rolled decoder regardless of the requested engine.
    if (config.arch == Arch::JVM)
        return std::make_unique<JvmDisassembler>();
    if (config.arch == Arch::GML)
        return std::make_unique<GmlDisassembler>(config);

    // Zydis decodes x86 real-mode/x86/x86-64 only. Every other architecture must go to Capstone
    // regardless of the requested engine, otherwise the bytes would be silently
    // decoded as x64.
    if (!ArchIsX86(config.arch))
        return std::make_unique<CapstoneDisassembler>(config);

    switch (config.engine) {
        case Engine::Zydis:    return std::make_unique<ZydisDisassembler>(config);
        case Engine::Capstone: return std::make_unique<CapstoneDisassembler>(config);
    }
    return std::make_unique<ZydisDisassembler>(config);
}

std::unique_ptr<IDisassembler> MakeDisassembler(Engine engine, Arch arch) {
    DecoderConfig config;
    config.engine = engine;
    config.arch = arch;
    return MakeDisassembler(config);
}

} // namespace ds
