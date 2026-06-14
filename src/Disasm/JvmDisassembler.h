#pragma once
//
// JvmDisassembler.h
// Hand-rolled JVM bytecode backend (javap-style mnemonics) implementing
// IDisassembler. Neither Zydis nor Capstone decodes Java bytecode, so this is
// a full opcode-table decoder: every standard opcode 0x00..0xC9, the `wide`
// prefix, and the variable-length tableswitch/lookupswitch (whose 4-byte
// padding is relative to the METHOD CODE START, not the instruction address).
//
// Optionally carries the parsed class file (attachClass) so that:
//   - constant-pool operands resolve to readable text in Instruction::comment
//     ("java/io/PrintStream.println:(Ljava/lang/String;)V", "\"hello\"", ...),
//   - invoke* of a method in THIS class resolves branchTarget to the local
//     method's code VA (call graph + click-to-follow work),
//   - switch padding uses the true bytecode index (bci = va - codeStart).
// Without a class, operands stay as raw "#n" indices and switch padding falls
// back to assuming the disassembly window started at a code-array start
// (true for the per-method sections BinaryFile maps for BinFormat::JavaClass).
//
#include "IDisassembler.h"
#include "../Core/JvmClass.h"

#include <memory>
#include <unordered_map>

namespace ds {

class JvmDisassembler : public IDisassembler {
public:
    JvmDisassembler() = default;

    // Attach the parsed class file for symbolication. Requires the identity
    // VA == file-offset mapping the JavaClass loader uses (imageBase 0).
    void attachClass(std::shared_ptr<const JvmClassFile> cf);

    Engine engine() const override { return Engine::Capstone; } // factory routes JVM itself; persisted name stays valid
    const char* engineName() const override { return "JVM bytecode"; }

    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t virtualAddress,
                                         size_t maxInstructions = 0) override;
    bool decodeOne(const uint8_t* data, size_t size,
                   uint64_t virtualAddress, Instruction& out) override;

private:
    // Decode one instruction whose bytecode index inside its method is `bci`
    // (needed only for tableswitch/lookupswitch padding).
    bool decodeAt(const uint8_t* d, size_t n, uint64_t va, uint32_t bci,
                  Instruction& out) const;
    // Best-effort bci for a lone decodeOne call (class context, else va).
    uint32_t bciFor(uint64_t va) const;

    std::shared_ptr<const JvmClassFile>        class_;
    std::unordered_map<std::string, uint32_t>  localMethodOff_;  // "name:desc" -> codeOffset
};

// When `dis` is the JVM backend, attach a parsed class file so constant-pool
// operands symbolicate and switch padding uses true bytecode indices. No-op
// for every other backend (safe to call unconditionally after any load).
// Defined in JvmDisassembler.cpp (not the factory) so the cl test loop can
// link it without pulling the Zydis/Capstone backends in.
void AttachJvmClass(IDisassembler& dis, std::shared_ptr<const JvmClassFile> cf);

} // namespace ds
