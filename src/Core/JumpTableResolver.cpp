#include "JumpTableResolver.h"

#include "BinaryFile.h"
#include "InstructionReference.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <string>
#include <utility>

namespace ds {
namespace {

constexpr size_t kHardMaxEntries = 1024;
constexpr size_t kThumbPredecessorBytes = 32;

static std::string lowerCopy(std::string value) {
    for (char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

static bool checkedAdd(uint64_t a, uint64_t b, uint64_t& out) {
    if (b > (std::numeric_limits<uint64_t>::max)() - a) return false;
    out = a + b;
    return true;
}

static bool checkedAddSigned(uint64_t base, int64_t displacement, uint64_t& out) {
    if (displacement >= 0)
        return checkedAdd(base, static_cast<uint64_t>(displacement), out);
    const uint64_t magnitude = static_cast<uint64_t>(-(displacement + 1)) + 1;
    if (magnitude > base) return false;
    out = base - magnitude;
    return true;
}

static bool readUnsigned(const uint8_t* p, size_t available, uint8_t width,
                         ByteOrder byteOrder, uint64_t& value) {
    value = 0;
    if (!p || available < width ||
        (width != 1 && width != 2 && width != 4 && width != 8))
        return false;
    if (byteOrder == ByteOrder::Big) {
        for (uint8_t i = 0; i < width; ++i) value = (value << 8) | p[i];
    } else {
        for (uint8_t i = 0; i < width; ++i)
            value |= static_cast<uint64_t>(p[i]) << (static_cast<unsigned>(i) * 8u);
    }
    return true;
}

static int64_t signed32(uint64_t value) {
    const uint64_t bits = value & 0xFFFFFFFFull;
    return (bits & 0x80000000ull)
         ? static_cast<int64_t>(bits) - 0x1'0000'0000ll
         : static_cast<int64_t>(bits);
}

static bool mappedAt(const BinaryFile& bin, uint64_t address, size_t bytes = 1) {
    if (!bytes) return false;
    size_t available = 0;
    return bin.ptrFromVA(address, available) != nullptr && available >= bytes;
}

static bool resolveMappedValue(const BinaryFile& bin, uint64_t value, uint64_t& address) {
    if (mappedAt(bin, value)) {
        address = value;
        return true;
    }
    uint64_t rebased = 0;
    if (checkedAdd(bin.imageBase(), value, rebased) && mappedAt(bin, rebased)) {
        address = rebased;
        return true;
    }
    return false;
}

// Return the number of file-backed executable bytes available from address.
// Static PE virtual padding and ELF SHT_NOBITS tails are deliberately excluded.
static size_t executableBytesAt(const BinaryFile& bin, uint64_t address) {
    for (const Section& section : bin.sections()) {
        if (!section.executable) continue;
        uint64_t begin = 0;
        if (!checkedAdd(bin.imageBase(), section.virtualAddress, begin) || address < begin)
            continue;
        const uint64_t offset = address - begin;
        uint64_t declared = section.rawSize;
        if (bin.isMappedImage()) declared = std::max(section.rawSize, section.virtualSize);
        if (!declared || offset >= declared) continue;
        size_t available = 0;
        if (!bin.ptrFromVA(address, available) || !available) continue;
        const uint64_t left = declared - offset;
        return static_cast<size_t>(std::min<uint64_t>(available, left));
    }
    return 0;
}

static bool validExecutableTarget(const BinaryFile& bin, IDisassembler& dis,
                                  uint64_t target) {
    const uint32_t alignment = std::max<uint32_t>(1, dis.instructionAlignment());
    if (target % alignment != 0) return false;
    const size_t executable = executableBytesAt(bin, target);
    if (!executable) return false;
    size_t available = 0;
    const uint8_t* p = bin.ptrFromVA(target, available);
    const size_t limit = std::min<size_t>({available, executable, 32});
    Instruction decoded;
    return p && limit && dis.decodeOne(p, limit, target, decoded) && decoded.length &&
           decoded.length <= limit && lowerCopy(decoded.mnemonic) != "db";
}

struct X86TableShape {
    bool     valid = false;
    uint64_t address = 0;
    uint8_t  width = 0;
};

struct X86DispatchPlan {
    bool valid = false;
    X86TableShape shape;
    JumpTableEncoding encoding = JumpTableEncoding::None;
    std::string evidence;
};

static bool parseHex(const std::string& text, size_t at, uint64_t& value, size_t& end) {
    value = 0;
    end = at;
    if (at + 2 > text.size() || text[at] != '0' ||
        (text[at + 1] != 'x' && text[at + 1] != 'X'))
        return false;
    size_t i = at + 2;
    const size_t first = i;
    while (i < text.size() && std::isxdigit(static_cast<unsigned char>(text[i]))) {
        const unsigned digit = std::isdigit(static_cast<unsigned char>(text[i]))
            ? static_cast<unsigned>(text[i] - '0')
            : static_cast<unsigned>(std::tolower(static_cast<unsigned char>(text[i])) - 'a' + 10);
        if (value > ((std::numeric_limits<uint64_t>::max)() - digit) / 16u) return false;
        value = value * 16u + digit;
        ++i;
    }
    if (i == first) return false;
    end = i;
    return true;
}

static bool pcRelativeTableAddress(const Instruction& instruction,
                                   const TypedOperand& operand,
                                   uint64_t& address) {
    if (InstructionUsesRuntimeSegment(instruction, operand) || !operand.displacementValid ||
        (operand.baseRegister != "rip" && operand.baseRegister != "eip"))
        return false;
    uint64_t next = 0;
    return checkedAdd(instruction.address, instruction.length, next) &&
           checkedAddSigned(next, operand.displacement, address);
}

static X86TableShape x86TableShape(const BinaryFile& bin,
                                   const Instruction& instruction) {
    for (const TypedOperand& operand : instruction.typedOperands) {
        if (operand.kind != OperandKind::Memory || operand.indexRegister.empty() ||
            (operand.scale != 2 && operand.scale != 4 && operand.scale != 8))
            continue;
        if (InstructionUsesRuntimeSegment(instruction, operand)) continue;
        uint64_t table = 0;
        if (pcRelativeTableAddress(instruction, operand, table) && mappedAt(bin, table))
            return {true, table, static_cast<uint8_t>(operand.scale)};
        if (operand.baseRegister.empty() && operand.displacementValid && operand.displacement >= 0 &&
            resolveMappedValue(bin, static_cast<uint64_t>(operand.displacement), table))
            return {true, table, static_cast<uint8_t>(operand.scale)};
    }

    if (!instruction.typedOperands.empty() || InstructionTextUsesRuntimeSegment(instruction)) return {};
    const std::string operands = lowerCopy(instruction.operands);
    const size_t lb = operands.find('[');
    const size_t rb = lb == std::string::npos ? std::string::npos : operands.find(']', lb + 1);
    if (lb == std::string::npos) return {};
    const size_t limit = rb == std::string::npos ? operands.size() : rb;
    std::string compact;
    compact.reserve(limit - lb);
    for (size_t i = lb; i < limit; ++i)
        if (!std::isspace(static_cast<unsigned char>(operands[i]))) compact.push_back(operands[i]);
    uint8_t width = compact.find("*8") != std::string::npos ? 8 :
                    compact.find("*4") != std::string::npos ? 4 :
                    compact.find("*2") != std::string::npos ? 2 : 0;
    if (!width) return {};

    // Legacy text-only decoders retain RIP/EIP symbolically.  Resolve that form
    // before treating the displacement as an absolute VA/RVA.
    for (const char* reg : {"rip", "eip"}) {
        const size_t pos = operands.find(reg, lb + 1);
        if (pos == std::string::npos || pos >= limit) continue;
        size_t signAt = pos + 3;
        while (signAt < limit && std::isspace(static_cast<unsigned char>(operands[signAt]))) ++signAt;
        if (signAt >= limit || (operands[signAt] != '+' && operands[signAt] != '-')) continue;
        size_t number = signAt + 1;
        while (number < limit && std::isspace(static_cast<unsigned char>(operands[number]))) ++number;
        uint64_t magnitude = 0; size_t end = 0;
        if (!parseHex(operands, number, magnitude, end)) continue;
        uint64_t next = 0, table = 0;
        if (!checkedAdd(instruction.address, instruction.length, next)) continue;
        const bool ok = operands[signAt] == '+'
            ? checkedAdd(next, magnitude, table)
            : magnitude <= next && (table = next - magnitude, true);
        if (ok && mappedAt(bin, table)) return {true, table, width};
    }

    X86TableShape result;
    for (size_t i = lb + 1; i + 2 <= limit; ++i) {
        uint64_t value = 0; size_t end = 0;
        if (!parseHex(operands, i, value, end)) continue;
        uint64_t table = 0;
        if (resolveMappedValue(bin, value, table)) result = {true, table, width};
        i = end - 1;
    }
    return result;
}

static const TypedOperand* memoryOperand(const Instruction& instruction) {
    const TypedOperand* found = nullptr;
    for (const TypedOperand& operand : instruction.typedOperands) {
        if (operand.kind != OperandKind::Memory) continue;
        if (found) return nullptr;
        found = &operand;
    }
    return found;
}

static std::string firstRegister(const Instruction& instruction) {
    for (const TypedOperand& operand : instruction.typedOperands)
        if (operand.kind == OperandKind::Register)
            return lowerCopy(operand.registerName);
    std::string text = lowerCopy(instruction.operands);
    const size_t comma = text.find(',');
    if (comma != std::string::npos) text.resize(comma);
    text.erase(std::remove_if(text.begin(), text.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    }), text.end());
    return text.find('[') == std::string::npos ? text : std::string();
}

static std::string x86RegisterFamily(std::string name) {
    name = lowerCopy(std::move(name));
    static const std::pair<const char*, const char*> aliases[] = {
        {"eax","rax"},{"ax","rax"},{"al","rax"},{"ah","rax"},
        {"ebx","rbx"},{"bx","rbx"},{"bl","rbx"},{"bh","rbx"},
        {"ecx","rcx"},{"cx","rcx"},{"cl","rcx"},{"ch","rcx"},
        {"edx","rdx"},{"dx","rdx"},{"dl","rdx"},{"dh","rdx"},
        {"esi","rsi"},{"si","rsi"},{"sil","rsi"},
        {"edi","rdi"},{"di","rdi"},{"dil","rdi"},
        {"ebp","rbp"},{"bp","rbp"},{"bpl","rbp"},
        {"esp","rsp"},{"sp","rsp"},{"spl","rsp"},
    };
    for (const auto& alias : aliases)
        if (name == alias.first) return alias.second;
    if (name.size() >= 3 && name[0] == 'r' &&
        std::isdigit(static_cast<unsigned char>(name[1]))) {
        while (!name.empty() && (name.back() == 'd' || name.back() == 'w' ||
                                 name.back() == 'b'))
            name.pop_back();
    }
    return name;
}

static bool typedRegister(const TypedOperand& operand, const std::string& expected) {
    return operand.kind == OperandKind::Register &&
           x86RegisterFamily(operand.registerName) == x86RegisterFamily(expected);
}

static bool constantComponent(const BinaryFile& bin, const Instruction& instruction,
                              const TypedOperand& memory, uint64_t& address) {
    if (InstructionUsesRuntimeSegment(instruction, memory)) return false;
    const std::string base = lowerCopy(memory.baseRegister);
    if (memory.pcRelative || base == "rip" || base == "eip")
        return pcRelativeTableAddress(instruction, memory, address);
    if (!base.empty() || !memory.displacementValid || memory.displacement < 0) return false;
    return resolveMappedValue(bin, static_cast<uint64_t>(memory.displacement), address);
}

// Decode every exact predecessor stream ending at the dispatch instruction.
// Trying each possible start handles variable-width x86 without accepting a
// stream that merely overlaps the instruction boundary.
static std::vector<std::vector<Instruction>> predecessorStreams(
    const BinaryFile& bin, IDisassembler& dis, const Instruction& dispatch) {
    constexpr size_t kMaxBack = 32;
    constexpr size_t kMaxInstructions = 8;
    std::vector<std::vector<Instruction>> streams;
    for (size_t back = 1; back <= kMaxBack && dispatch.address >= back; ++back) {
        const uint64_t start = dispatch.address - back;
        if (executableBytesAt(bin, start) < back) continue;
        size_t available = 0;
        const uint8_t* bytes = bin.ptrFromVA(start, available);
        if (!bytes || available < back) continue;
        std::vector<Instruction> stream;
        size_t offset = 0;
        while (offset < back && stream.size() < kMaxInstructions) {
            Instruction decoded;
            if (!dis.decodeOne(bytes + offset, back - offset, start + offset, decoded) ||
                !decoded.length || decoded.length > back - offset)
                break;
            decoded.address = start + offset;
            offset += decoded.length;
            stream.push_back(std::move(decoded));
        }
        if (offset == back && !stream.empty()) streams.push_back(std::move(stream));
    }
    return streams;
}

static bool loadTableEntry(const BinaryFile& bin, const Instruction& load,
                           const std::string& jumpRegister,
                           X86TableShape& shape, std::string& mnemonic,
                           uint16_t& destinationWidth) {
    mnemonic = lowerCopy(load.mnemonic);
    if (mnemonic != "mov" && mnemonic != "movsxd" && mnemonic != "movsx") return false;
    if (load.typedOperands.size() < 2 ||
        !typedRegister(load.typedOperands[0], jumpRegister) ||
        load.typedOperands[1].kind != OperandKind::Memory)
        return false;
    destinationWidth = load.typedOperands[0].widthBits;
    // On x86-64 a 32-bit destination is the only narrower write that defines
    // the whole register (zero-extension). Byte/word partial writes cannot prove
    // the value consumed by a later 64-bit register jump.
    if (destinationWidth && destinationWidth < 32) return false;
    shape = x86TableShape(bin, load);
    return shape.valid;
}

static bool addBaseEvidence(const BinaryFile& bin,
                            const std::vector<Instruction>& stream,
                            const Instruction& load, const Instruction& add,
                            const std::string& jumpRegister,
                            const X86TableShape& shape,
                            JumpTableEncoding& encoding,
                            std::string& evidence) {
    if (lowerCopy(add.mnemonic) != "add" || add.typedOperands.size() < 2 ||
        !typedRegister(add.typedOperands[0], jumpRegister))
        return false;

    uint64_t base = 0;
    const TypedOperand& source = add.typedOperands[1];
    if (source.kind == OperandKind::Immediate || source.kind == OperandKind::Pointer) {
        base = source.immediate;
    } else if (source.kind == OperandKind::Register) {
        const std::string baseRegister = lowerCopy(source.registerName);
        if (stream.size() < 3) return false;
        const Instruction& lea = stream[stream.size() - 3];
        if (lowerCopy(lea.mnemonic) != "lea" || lea.typedOperands.size() < 2 ||
            !typedRegister(lea.typedOperands[0], baseRegister) ||
            lea.typedOperands[1].kind != OperandKind::Memory)
            return false;
        const TypedOperand& addressOperand = lea.typedOperands[1];
        if (!constantComponent(bin, lea, addressOperand, base)) return false;

        // Per-slot bases prove next-slot-relative entries only when the LEA uses
        // the same index/scale as the load and its constant component is T+4.
        const TypedOperand* loadMemory = memoryOperand(load);
        if (loadMemory && !loadMemory->indexRegister.empty() &&
            lowerCopy(loadMemory->indexRegister) == lowerCopy(addressOperand.indexRegister) &&
            loadMemory->scale == 4 && addressOperand.scale == 4 &&
            shape.address <= (std::numeric_limits<uint64_t>::max)() - 4 &&
            base == shape.address + 4) {
            encoding = JumpTableEncoding::RelativeToNextSlot;
            evidence = "decoded load + indexed LEA(T+index*4+4) + add + register jump";
            return true;
        }
    } else {
        return false;
    }

    if (base == shape.address) {
        encoding = JumpTableEncoding::RelativeToTable;
        evidence = "decoded signed table load + add(table base) + register jump";
        return true;
    }
    if (base == bin.imageBase()) {
        encoding = JumpTableEncoding::RVA;
        evidence = "decoded table load + add(image base) + register jump";
        return true;
    }
    return false;
}

static X86DispatchPlan x86DispatchPlan(const BinaryFile& bin, IDisassembler& dis,
                                       const Instruction& instruction) {
    // A direct memory-indirect jump consumes the stored bit pattern as the
    // destination. No arithmetic exists that could justify RVA/rel32 decoding.
    if (InstructionHasMemoryOperand(instruction) ||
        instruction.operands.find('[') != std::string::npos) {
        X86TableShape shape = x86TableShape(bin, instruction);
        if (shape.valid)
            return {true, shape, JumpTableEncoding::AbsoluteVA,
                    "direct memory-indirect jump semantics"};
        return {};
    }

    const std::string jumpRegister = firstRegister(instruction);
    if (jumpRegister.empty()) return {};
    uint16_t jumpWidth = 0;
    for (const TypedOperand& operand : instruction.typedOperands)
        if (operand.kind == OperandKind::Register) {
            jumpWidth = operand.widthBits;
            break;
        }
    X86DispatchPlan accepted;
    for (const std::vector<Instruction>& stream : predecessorStreams(bin, dis, instruction)) {
        if (stream.empty()) continue;
        X86TableShape shape;
        std::string loadMnemonic;
        uint16_t loadWidth = 0;
        JumpTableEncoding encoding = JumpTableEncoding::None;
        std::string evidence;
        if (loadTableEntry(bin, stream.back(), jumpRegister, shape, loadMnemonic,
                           loadWidth)) {
            encoding = JumpTableEncoding::AbsoluteVA;
            evidence = "decoded table load immediately followed by register jump";
        } else if (stream.size() >= 2 &&
                   loadTableEntry(bin, stream[stream.size() - 2], jumpRegister,
                                  shape, loadMnemonic, loadWidth) &&
                   addBaseEvidence(bin, stream, stream[stream.size() - 2], stream.back(),
                                   jumpRegister, shape, encoding, evidence)) {
            if ((encoding == JumpTableEncoding::RelativeToTable ||
                 encoding == JumpTableEncoding::RelativeToNextSlot) &&
                loadMnemonic != "movsxd" && loadMnemonic != "movsx")
                continue; // rel32 entries require an explicit signed load
            if ((encoding == JumpTableEncoding::RelativeToTable ||
                 encoding == JumpTableEncoding::RelativeToNextSlot) &&
                jumpWidth == 64 && loadWidth != 64)
                continue; // sign extension must define the consumed 64-bit family
        } else {
            continue;
        }
        X86DispatchPlan candidate{true, shape, encoding, evidence};
        if (!accepted.valid) accepted = std::move(candidate);
        else if (accepted.shape.address != candidate.shape.address ||
                 accepted.shape.width != candidate.shape.width ||
                 accepted.encoding != candidate.encoding)
            return {}; // overlapping predecessor decodes disagree: unresolved
    }
    return accepted;
}

static bool resolveEncodedTarget(const BinaryFile& bin, JumpTableEncoding encoding,
                                 uint64_t table, uint64_t slot, uint64_t stored,
                                 uint64_t& target) {
    switch (encoding) {
        case JumpTableEncoding::AbsoluteVA:
            target = stored;
            return true;
        case JumpTableEncoding::RVA:
            return checkedAdd(bin.imageBase(), stored, target);
        case JumpTableEncoding::RelativeToTable:
            return checkedAddSigned(table, signed32(stored), target);
        case JumpTableEncoding::RelativeToNextSlot: {
            uint64_t next = 0;
            return checkedAdd(slot, 4, next) && checkedAddSigned(next, signed32(stored), target);
        }
        default:
            return false;
    }
}

static JumpTableResolution tryX86Encoding(const BinaryFile& bin, IDisassembler& dis,
                                          ByteOrder byteOrder, uint64_t table,
                                          uint8_t width, JumpTableEncoding encoding,
                                          size_t maxEntries) {
    JumpTableResolution out;
    out.tableAddress = table;
    out.entryWidth = width;
    out.encoding = encoding;
    for (size_t i = 0; i < maxEntries; ++i) {
        if (i > (std::numeric_limits<uint64_t>::max)() / width) break;
        uint64_t slot = 0;
        if (!checkedAdd(table, static_cast<uint64_t>(i) * width, slot)) break;
        size_t available = 0;
        const uint8_t* p = bin.ptrFromVA(slot, available);
        uint64_t stored = 0, target = 0;
        if (!readUnsigned(p, available, width, byteOrder, stored) ||
            !resolveEncodedTarget(bin, encoding, table, slot, stored, target) ||
            !validExecutableTarget(bin, dis, target))
            break;
        out.targets.push_back(target);
    }
    if (out.targets.size() < 2) {
        out.targets.clear();
        return out;
    }

    uint64_t tableEnd = 0;
    const uint64_t byteCount = static_cast<uint64_t>(out.targets.size()) * width;
    if (!checkedAdd(table, byteCount, tableEnd)) {
        out.targets.clear();
        return out;
    }
    for (uint64_t target : out.targets) {
        if (target >= table && target < tableEnd) {
            out.targets.clear();
            return out;
        }
    }

    out.valid = true;
    out.truncated = out.targets.size() == maxEntries;
    out.evidence = std::to_string(out.targets.size()) + " decoder-valid executable target(s), " +
                   JumpTableEncodingName(encoding) + " encoding";
    if (out.truncated) out.evidence += " (entry cap reached)";
    return out;
}

static std::string thumbIndexRegister(const Instruction& instruction) {
    for (const TypedOperand& operand : instruction.typedOperands)
        if (operand.kind == OperandKind::Memory && operand.baseRegister == "pc" &&
            !operand.indexRegister.empty())
            return lowerCopy(operand.indexRegister);

    const std::string operands = lowerCopy(instruction.operands);
    const size_t lb = operands.find('[');
    const size_t comma = lb == std::string::npos ? std::string::npos : operands.find(',', lb + 1);
    if (comma == std::string::npos) return {};
    size_t begin = comma + 1;
    while (begin < operands.size() && std::isspace(static_cast<unsigned char>(operands[begin]))) ++begin;
    size_t end = begin;
    while (end < operands.size() &&
           (std::isalnum(static_cast<unsigned char>(operands[end])) || operands[end] == '_')) ++end;
    return operands.substr(begin, end - begin);
}

static bool compareBound(const Instruction& instruction, const std::string& index,
                         size_t& count) {
    const std::string mnemonic = lowerCopy(instruction.mnemonic);
    if (mnemonic != "cmp" && mnemonic != "cmp.w") return false;
    if (instruction.typedOperands.size() >= 2) {
        const TypedOperand& lhs = instruction.typedOperands[0];
        const TypedOperand& rhs = instruction.typedOperands[1];
        if (lhs.kind == OperandKind::Register && lowerCopy(lhs.registerName) == index &&
            rhs.kind == OperandKind::Immediate && rhs.immediate < kHardMaxEntries) {
            count = static_cast<size_t>(rhs.immediate) + 1;
            return true;
        }
    }
    const std::string operands = lowerCopy(instruction.operands);
    if (operands.rfind(index, 0) != 0) return false;
    const size_t hash = operands.find('#');
    if (hash == std::string::npos) return false;
    char* end = nullptr;
    const unsigned long long bound = std::strtoull(operands.c_str() + hash + 1, &end, 0);
    if (!end || end == operands.c_str() + hash + 1 || bound >= kHardMaxEntries) return false;
    count = static_cast<size_t>(bound) + 1;
    return true;
}

static size_t inferThumbCount(const BinaryFile& bin, IDisassembler& dis,
                              const Instruction& instruction,
                              const std::string& index) {
    if (index.empty()) return 0;
    for (size_t back = 2; back <= kThumbPredecessorBytes && instruction.address >= back; back += 2) {
        const uint64_t start = instruction.address - back;
        if (executableBytesAt(bin, start) < back) continue;
        size_t available = 0;
        const uint8_t* p = bin.ptrFromVA(start, available);
        if (!p || available < back) continue;
        std::vector<Instruction> previous;
        size_t offset = 0;
        while (offset < back && previous.size() < 20) {
            Instruction decoded;
            if (!dis.decodeOne(p + offset, back - offset, start + offset, decoded) ||
                !decoded.length || decoded.length > back - offset)
                break;
            decoded.address = start + offset;
            previous.push_back(std::move(decoded));
            offset += previous.back().length;
        }
        if (offset != back) continue;
        for (auto it = previous.rbegin(); it != previous.rend(); ++it) {
            size_t count = 0;
            if (compareBound(*it, index, count)) return count;
        }
    }
    return 0;
}

static JumpTableResolution resolveThumb(const BinaryFile& bin, IDisassembler& dis,
                                        ByteOrder byteOrder,
                                        const Instruction& instruction,
                                        size_t maxEntries) {
    JumpTableResolution out;
    const std::string mnemonic = lowerCopy(instruction.mnemonic);
    const bool halfword = mnemonic == "tbh";
    if (mnemonic != "tbb" && !halfword) return out;
    if (instruction.address & 1u) return out; // analysis VAs are canonical, not Thumb-bit pointers
    const std::string index = thumbIndexRegister(instruction);
    if (index.empty()) return out;
    if (instruction.address > (std::numeric_limits<uint64_t>::max)() - 4) return out;
    const uint64_t pc = instruction.address + 4;
    const uint64_t table = pc & ~uint64_t{3};
    const uint8_t width = halfword ? 2 : 1;
    if (!mappedAt(bin, table, width)) return out;

    const size_t inferred = inferThumbCount(bin, dis, instruction, index);
    // Without a decoded bounds check, adjacent literal/code-pointer data is
    // indistinguishable from more cases. Fail unresolved instead of accepting
    // an arbitrary validated prefix as a switch.
    if (!inferred) return out;
    const size_t wanted = std::min(inferred, maxEntries);
    if (!wanted) return out;
    uint64_t tableEnd = 0;
    if (!checkedAdd(table, static_cast<uint64_t>(wanted) * width, tableEnd)) return out;

    out.tableAddress = table;
    out.entryWidth = width;
    out.encoding = halfword ? JumpTableEncoding::ThumbTBH : JumpTableEncoding::ThumbTBB;
    for (size_t i = 0; i < wanted; ++i) {
        uint64_t slot = 0;
        if (!checkedAdd(table, static_cast<uint64_t>(i) * width, slot)) break;
        size_t available = 0;
        const uint8_t* p = bin.ptrFromVA(slot, available);
        uint64_t encoded = 0;
        if (!readUnsigned(p, available, width, byteOrder, encoded)) break;
        uint64_t displacement = encoded * 2u;
        uint64_t target = 0;
        if (!checkedAdd(pc, displacement, target) || (target & 1u) ||
            (target >= table && target < tableEnd) ||
            !validExecutableTarget(bin, dis, target))
            break;
        out.targets.push_back(target);
    }
    if (out.targets.size() != wanted) {
        out.targets.clear();
        return out;
    }

    out.valid = true;
    out.truncated = inferred > maxEntries;
    out.evidence = std::to_string(out.targets.size()) + " decoder-valid executable target(s), " +
                   std::string(halfword ? "Thumb TBH" : "Thumb TBB") +
                   " with a decoded CMP bound";
    if (out.truncated) out.evidence += " (entry cap reached)";
    return out;
}

} // namespace

const char* JumpTableEncodingName(JumpTableEncoding encoding) {
    switch (encoding) {
        case JumpTableEncoding::None:               return "none";
        case JumpTableEncoding::AbsoluteVA:         return "absolute VA";
        case JumpTableEncoding::RVA:                return "image-relative RVA";
        case JumpTableEncoding::RelativeToTable:    return "signed rel32 from table base";
        case JumpTableEncoding::RelativeToNextSlot: return "signed rel32 from next slot";
        case JumpTableEncoding::ThumbTBB:           return "Thumb TBB";
        case JumpTableEncoding::ThumbTBH:           return "Thumb TBH";
    }
    return "unknown";
}

JumpTableResolution ResolveJumpTable(const BinaryFile& bin,
                                     IDisassembler& dis,
                                     Arch arch,
                                     ByteOrder byteOrder,
                                     const Instruction& instruction,
                                     size_t maxEntries) {
    maxEntries = std::clamp<size_t>(maxEntries, 1, kHardMaxEntries);
    if (!bin.loaded() || !dis.ready()) return {};
    if (arch == Arch::THUMB)
        return resolveThumb(bin, dis, byteOrder, instruction, maxEntries);
    if (!ArchIsX86(arch)) return {};

    const std::string mnemonic = lowerCopy(instruction.mnemonic);
    const bool indirectJump = instruction.flow.kind == FlowKind::IndirectBranch ||
        ((mnemonic == "jmp" || mnemonic == "jmpq") && !HasBranchTarget(instruction));
    if (!indirectJump || InstructionIsCall(instruction) || InstructionIsReturn(instruction))
        return {};
    const X86DispatchPlan plan = x86DispatchPlan(bin, dis, instruction);
    if (!plan.valid || !mappedAt(bin, plan.shape.address, plan.shape.width)) return {};
    JumpTableResolution result = tryX86Encoding(
        bin, dis, byteOrder, plan.shape.address, plan.shape.width,
        plan.encoding, maxEntries);
    if (result.valid) result.evidence += "; " + plan.evidence;
    return result;
}

JumpTableResolution ResolveJumpTable(const BinaryFile& bin,
                                     IDisassembler& dis,
                                     Arch arch,
                                     const Instruction& instruction,
                                     size_t maxEntries) {
    return ResolveJumpTable(bin, dis, arch,
        bin.bigEndian() ? ByteOrder::Big : ByteOrder::Little,
        instruction, maxEntries);
}

} // namespace ds
