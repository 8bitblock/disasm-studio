#include "DisassemblerFactory.h"
#include "ZydisDisassembler.h"
#include "CapstoneDisassembler.h"
#include "JvmDisassembler.h"

namespace ds {

std::unique_ptr<IDisassembler> MakeDisassembler(Engine engine, Arch arch) {
    // Java bytecode has no Zydis/Capstone backend; it always uses the
    // hand-rolled decoder regardless of the requested engine.
    if (arch == Arch::JVM)
        return std::make_unique<JvmDisassembler>();

    // Zydis decodes x86/x86-64 only. Every other architecture must go to Capstone
    // regardless of the requested engine, otherwise the bytes would be silently
    // decoded as x64.
    if (!ArchIsX86(arch))
        return std::make_unique<CapstoneDisassembler>(arch);

    switch (engine) {
        case Engine::Zydis:    return std::make_unique<ZydisDisassembler>(arch);
        case Engine::Capstone: return std::make_unique<CapstoneDisassembler>(arch);
    }
    return std::make_unique<ZydisDisassembler>(arch);
}

} // namespace ds
