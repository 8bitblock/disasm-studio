#pragma once
#include "IDisassembler.h"
#include <memory>

namespace ds {

// Builds a concrete disassembler for the requested engine + architecture.
// The UI holds an IDisassembler* and never knows which engine it got.
std::unique_ptr<IDisassembler> MakeDisassembler(const DecoderConfig& config);

// Backward-compatible shorthand using little endian and default features.
std::unique_ptr<IDisassembler> MakeDisassembler(Engine engine, Arch arch);

} // namespace ds
