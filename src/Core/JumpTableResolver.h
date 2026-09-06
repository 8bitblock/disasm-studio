#pragma once
//
// JumpTableResolver.h
// Shared, bounded native jump-table recovery.  The resolver reads only the
// immutable BinaryFile image and validates every recovered destination against
// executable, file-backed storage and the caller-owned decoder.
//

#include "../Disasm/IDisassembler.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;

enum class JumpTableEncoding : uint8_t {
    None = 0,
    AbsoluteVA,
    RVA,
    RelativeToTable,
    RelativeToNextSlot,
    ThumbTBB,
    ThumbTBH,
};

struct JumpTableResolution {
    // `valid` is intentionally separate from tableAddress: a raw image mapped
    // at VA zero may contain a perfectly valid table at address zero.
    bool                    valid = false;
    uint64_t                tableAddress = 0;
    uint8_t                 entryWidth = 0;
    JumpTableEncoding       encoding = JumpTableEncoding::None;
    std::vector<uint64_t>   targets;
    std::string             evidence;
    // True when the caller's (at most 1,024-entry) budget was reached while
    // every entry examined so far remained valid.
    bool                    truncated = false;
};

const char* JumpTableEncodingName(JumpTableEncoding encoding);

// Resolve x86 memory-indirect absolute/RVA/relative tables and Thumb TBB/TBH.
// maxEntries is clamped to [1, 1024].  Byte order is explicit so Raw callers
// can use analyst-selected settings; the overload below uses BinaryFile's
// authoritative structured-image byte order.
JumpTableResolution ResolveJumpTable(const BinaryFile& bin,
                                     IDisassembler& dis,
                                     Arch arch,
                                     ByteOrder byteOrder,
                                     const Instruction& instruction,
                                     size_t maxEntries = 1024);

JumpTableResolution ResolveJumpTable(const BinaryFile& bin,
                                     IDisassembler& dis,
                                     Arch arch,
                                     const Instruction& instruction,
                                     size_t maxEntries = 1024);

} // namespace ds
