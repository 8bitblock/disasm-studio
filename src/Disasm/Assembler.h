#pragma once
//
// Assembler.h
// Thin wrapper over Keystone for turning assembly text into machine code, used
// by the Binary View's live "Patch" feature (type `mov rax, 1` -> bytes).
//
#include "IDisassembler.h"   // Arch
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

struct AsmResult {
    bool                 ok = false;
    std::vector<uint8_t> bytes;
    size_t               count = 0;   // number of instructions encoded
    std::string          error;       // human-readable message when !ok
};

// Assemble one or more instructions (';' or newline separated) for `arch`,
// resolving relative operands against `address`. Intel syntax.
AsmResult Assemble(Arch arch, const std::string& text, uint64_t address);

} // namespace ds
