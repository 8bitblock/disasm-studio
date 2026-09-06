#include "GameMakerRunner.h"
#include <algorithm>
#include <cstring>

namespace ds {
namespace {
constexpr GmlRunnerProfile kNubby {
    1, "Nubby's Number Factory x64 VM (Steam build 25109973)",
    "5664918ea125b0d1d763d51fe84ce10ef974dab8ded1014026ffda69fb433f1e",
    0x00a6f000,
    {0x285c60, 5, {0x48, 0x89, 0x54, 0x24, 0x10}},
    {0x285e16, 6, {0x89, 0x8b, 0x9c, 0x00, 0x00, 0x00}},
    0x749768, 0x76ca40, 0xa1d970, 0xa1d968, 0x75981b, 0x5e32f0, 0x5e3340,
    0x73dad0,
    {0xeccd0, 5, {0x48, 0x89, 0x5c, 0x24, 0x10}},
    {0xed0a0, 5, {0x48, 0x89, 0x5c, 0x24, 0x08}},
    GmlCapabilityBit(GmlRunnerCapability::InstructionStops)|GmlCapabilityBit(GmlRunnerCapability::CallAwareSteps)|
    GmlCapabilityBit(GmlRunnerCapability::Frames)|GmlCapabilityBit(GmlRunnerCapability::Globals)|
    GmlCapabilityBit(GmlRunnerCapability::Instances)|GmlCapabilityBit(GmlRunnerCapability::Locals)|
    GmlCapabilityBit(GmlRunnerCapability::NumericEdits)
};
constexpr uint64_t kMaxUserAddress = 0x00007fffffffffffULL;
bool range(uint64_t address, size_t size) noexcept {
    return address >= 0x10000 && address <= kMaxUserAddress &&
        size && size <= kMaxUserAddress - address + 1;
}
template<class T> T field(const uint8_t* bytes, size_t offset) noexcept {
    T value{};
    std::memcpy(&value, bytes + offset, sizeof(value));
    return value;
}
bool spanIn(uint64_t address, size_t size, uint64_t begin, uint64_t end) noexcept {
    return address >= begin && address <= end && size <= end - address;
}
bool fail(const char** error, const char* text) noexcept {
    if (error) *error = text;
    return false;
}
}

bool GmlRunnerReader::copy(uint64_t address, void* output, size_t size) const noexcept {
    return read && output && range(address, size) && read(owner, address, output, size);
}
const GmlRunnerProfile& NubbyGameMakerRunner() noexcept { return kNubby; }
const GmlRunnerProfile* MatchGameMakerRunner(std::string_view sha256) noexcept {
    if (sha256.size() != kNubby.sha256.size()) return nullptr;
    for (size_t i = 0; i < sha256.size(); ++i) {
        char c = sha256[i];
        if (c >= 'A' && c <= 'F') c = static_cast<char>(c + ('a' - 'A'));
        if (c != kNubby.sha256[i]) return nullptr;
    }
    return &kNubby;
}
bool ValidateGmlRunnerImage(const GmlRunnerReader& reader, uint64_t base,
                          const GmlRunnerProfile& profile, const char** error) noexcept {
    if (error) *error = nullptr;
    if (&profile != &kNubby || !range(base, profile.imageSize))
        return fail(error, "Unsupported runner profile or image range");
    uint8_t dos[64]{}, nt[88]{};
    if (!reader.copy(base, dos, sizeof(dos)) || field<uint16_t>(dos, 0) != 0x5a4d)
        return fail(error, "Runner DOS header is unreadable or changed");
    uint32_t ntOffset = field<uint32_t>(dos, 0x3c);
    if (ntOffset < 64 || ntOffset > 1024 * 1024 ||
        !reader.copy(base + ntOffset, nt, sizeof(nt)) ||
        field<uint32_t>(nt, 0) != 0x4550 || field<uint16_t>(nt, 4) != 0x8664 ||
        field<uint16_t>(nt, 24) != 0x20b || field<uint32_t>(nt, 24 + 56) != profile.imageSize)
        return fail(error, "Runner x64 image header disagrees with the exact adapter");
    for (const auto* site : {&profile.interpreterEntry, &profile.instructionDispatch,
                             &profile.instanceConstructor, &profile.instanceDestructor}) {
        uint8_t bytes[16]{};
        if (!reader.copy(base + site->rva, bytes, site->byteCount) ||
            std::memcmp(bytes, site->original.data(), site->byteCount) != 0)
            return fail(error, "Runner instrumentation bytes were changed or are already owned");
    }
    uint64_t ideDebugger = 0;
    if (!reader.copy(base + profile.debuggerObjectRva, &ideDebugger, sizeof(ideDebugger)) || ideDebugger)
        return fail(error, "GameMaker's IDE debugger path is active or unreadable");
    uint8_t modernNames = 0;
    if (!reader.copy(base + profile.modernNamesFlagRva, &modernNames, 1) || modernNames != 1)
        return fail(error, "Expected initialized modern runner variable table is unavailable");
    return true;
}

bool ReadGmlRunnerCode(const GmlRunnerReader& reader, uint64_t base, uint64_t address,
                      GmlRunnerCodeView& output) noexcept {
    output = {};
    uint8_t code[0xb8]{}, blob[0x30]{};
    if ((address & 7) || !reader.copy(address, code, sizeof(code)) ||
        field<uint64_t>(code, 0) != base + 0x633800 ||
        (field<uint32_t>(code, 0x10) != 1 && field<uint32_t>(code, 0x10) != 2) ||
        field<uint64_t>(code, 0x90) != 0) return false;
    const uint64_t blobAddress = field<uint64_t>(code, 0x68);
    if (!reader.copy(blobAddress, blob, sizeof(blob))) return false;
    GmlRunnerCodeView value;
    value.address = address;
    value.blob = blobAddress;
    value.bytecodeBase = field<uint64_t>(blob, 0x18);
    value.bytecodeLength = field<uint32_t>(blob, 8);
    value.nameAddress = field<uint64_t>(code, 0x80);
    value.codeIndex = field<uint32_t>(code, 0x88);
    value.entryOffset = field<uint32_t>(code, 0x9c);
    value.localsCount = field<uint32_t>(code, 0xa0);
    value.argumentsCount = field<uint32_t>(code, 0xa4);
    if (!value.bytecodeLength || value.bytecodeLength > kGmlRunnerMaxCodeBytes ||
        (value.bytecodeLength & 3) || (value.entryOffset & 3) ||
        value.entryOffset >= value.bytecodeLength || value.codeIndex >= 262144 ||
        value.localsCount > kGmlRunnerMaxObjectSlots || value.argumentsCount > 65535 ||
        !range(value.bytecodeBase, value.bytecodeLength) || !range(value.nameAddress, 1)) return false;
    output = value;
    return true;
}

bool ReadGmlRunnerContext(const GmlRunnerReader& reader, uint64_t base, uint64_t address,
    uint32_t pc, uint64_t stackTop, GmlRunnerContextView& output) noexcept {
    output = {};
    uint8_t raw[0xb0]{};
    if ((address & 7) || !reader.copy(address, raw, sizeof(raw))) return false;
    GmlRunnerContextView value;
    value.address = address;
    value.nativeParent = field<uint64_t>(raw, 8);
    value.operandBuffer = field<uint64_t>(raw, 0x10);
    value.localObject = field<uint64_t>(raw, 0x20);
    value.self = field<uint64_t>(raw, 0x28);
    value.other = field<uint64_t>(raw, 0x30);
    value.arguments = field<uint64_t>(raw, 0x40);
    value.argumentCount = field<uint32_t>(raw, 0x48);
    value.anchor = field<uint64_t>(raw, 0x58);
    value.operandCapacity = field<uint32_t>(raw, 0x88);
    value.logicalDepth = field<uint32_t>(raw, 0x94);
    value.operandStackTop = stackTop;
    value.byteOffset = pc;
    if (value.nativeParent == address || value.logicalDepth > 4096 ||
        value.operandCapacity < 0x1000 || value.operandCapacity > kGmlRunnerMaxOperandCapacity ||
        !range(value.operandBuffer, value.operandCapacity) || value.argumentCount > 4096 ||
        !ReadGmlRunnerCode(reader, base, field<uint64_t>(raw, 0x38), value.code)) return false;
    value.operandBufferEnd = value.operandBuffer + value.operandCapacity;
    if (field<uint64_t>(raw, 0x50) != value.code.bytecodeBase ||
        field<uint64_t>(raw, 0x60) != value.code.blob ||
        field<uint32_t>(raw, 0x98) != value.code.bytecodeLength ||
        field<uint32_t>(raw, 0x8c) != pc || (pc & 3) || pc < value.code.entryOffset ||
        pc > value.code.bytecodeLength || (stackTop && pc == value.code.bytecodeLength) ||
        !spanIn(value.anchor, 0x78, value.operandBuffer, value.operandBufferEnd) ||
        !spanIn(value.arguments, size_t(value.argumentCount) * 16, value.operandBuffer, value.operandBufferEnd) ||
        (stackTop && !spanIn(stackTop, 0, value.operandBuffer, value.anchor))) return false;
    uint32_t magic = 0;
    if (!reader.copy(value.anchor, &magic, sizeof(magic)) || magic != kGmlRunnerFrameMagic) return false;
    output = value;
    return true;
}

bool ReadGmlRunnerSavedFrame(const GmlRunnerReader& reader, uint64_t base,
    const GmlRunnerContextView& context, uint64_t anchor, GmlRunnerSavedFrameView& output) noexcept {
    output = {};
    uint8_t raw[0x78]{};
    if (!spanIn(anchor, sizeof(raw), context.operandBuffer, context.operandBufferEnd) ||
        !reader.copy(anchor, raw, sizeof(raw)) || field<uint32_t>(raw, 0) != kGmlRunnerFrameMagic) return false;
    const int32_t previousDistance = field<int32_t>(raw, 0x10);
    const int32_t argumentDistance = field<int32_t>(raw, 0x18);
    if (previousDistance < 0 || argumentDistance < 0 ||
        uint32_t(previousDistance) > context.operandCapacity ||
        uint32_t(argumentDistance) > context.operandCapacity) return false;
    GmlRunnerSavedFrameView value;
    value.anchor = anchor;
    value.previousAnchor = context.operandBufferEnd - previousDistance;
    value.arguments = context.operandBufferEnd - argumentDistance;
    value.argumentCount = field<uint32_t>(raw, 0x0c);
    value.returnOffset = field<uint32_t>(raw, 4);
    value.self = field<uint64_t>(raw, 0x20);
    value.other = field<uint64_t>(raw, 0x28);
    value.localObject = field<uint64_t>(raw, 0x60);
    if (value.previousAnchor <= anchor ||
        !spanIn(value.previousAnchor, 0x78, context.operandBuffer, context.operandBufferEnd) ||
        value.argumentCount > 4096 ||
        !spanIn(value.arguments, size_t(value.argumentCount) * 16, context.operandBuffer, context.operandBufferEnd) ||
        !ReadGmlRunnerCode(reader, base, field<uint64_t>(raw, 0x30), value.code) ||
        field<uint64_t>(raw, 0x38) != value.code.blob || (value.returnOffset & 3) ||
        value.returnOffset < value.code.entryOffset || value.returnOffset > value.code.bytecodeLength) return false;
    output = value;
    return true;
}

bool ReadGmlRunnerObject(const GmlRunnerReader& reader, uint64_t base, uint64_t address,
    GmlRunnerObjectView& output) noexcept {
    output = {};
    uint8_t raw[0x88]{};
    if ((address & 7) || !reader.copy(address, raw, sizeof(raw))) return false;
    const uint64_t vtable = field<uint64_t>(raw, 0);
    if (vtable != base + kNubby.objectVtableRva && vtable != base + kNubby.instanceVtableRva) return false;
    GmlRunnerObjectView value;
    value.address = address;
    value.directValues = field<uint64_t>(raw, 8);
    value.variableMap = field<uint64_t>(raw, 0x48);
    value.variableCapacity = field<uint32_t>(raw, 0x5c);
    value.type = field<uint32_t>(raw, 0x7c);
    if (value.variableCapacity > kGmlRunnerMaxObjectSlots) return false;
    value.isInstance = value.type == 1 && vtable == base + kNubby.instanceVtableRva;
    if (value.isInstance) {
        uint32_t ids[2]{};
        if (!reader.copy(address + 0xbc, ids, sizeof(ids))) return false;
        value.instanceNumber = ids[0];
        value.objectIndex = ids[1];
    }
    output = value;
    return true;
}
bool ReadGmlRunnerInstanceRegistry(const GmlRunnerReader& reader, uint64_t base,
    GmlRunnerInstanceRegistryView& output) noexcept {
    output = {};
    uint8_t raw[16]{};
    const uint64_t address = base + kNubby.instanceRegistryRva;
    if (!reader.copy(address, raw, sizeof(raw))) return false;
    GmlRunnerInstanceRegistryView value;
    value.address = address;
    value.buckets = field<uint64_t>(raw, 0);
    value.mask = field<uint32_t>(raw, 8);
    value.count = field<uint32_t>(raw, 12);
    if (value.mask >= kGmlRunnerMaxInstanceBuckets ||
        ((value.mask + 1) & value.mask) || value.count > kGmlRunnerMaxInstances ||
        (value.buckets & 7) || !range(value.buckets, size_t(value.mask + 1) * 16)) return false;
    output = value;
    return true;
}
bool EnumerateGmlRunnerInstances(const GmlRunnerReader& reader, uint64_t base,
    uint32_t maxRecords, GmlRunnerInstanceVisitor visitor, void* owner,
    GmlRunnerInstanceEnumeration& output) noexcept {
    output = {};
    GmlRunnerInstanceRegistryView registry;
    if (!visitor || maxRecords > kGmlRunnerMaxInstances ||
        !ReadGmlRunnerInstanceRegistry(reader, base, registry)) return false;
    output.registryCount = registry.count;
    for (uint32_t bucket = 0; bucket <= registry.mask; ++bucket) {
        uint64_t ends[2]{};
        if (!reader.copy(registry.buckets + uint64_t(bucket) * 16, ends, sizeof(ends)) ||
            ((!ends[0]) != (!ends[1]))) return false;
        uint64_t node = ends[0], previous = 0;
        while (node) {
            // A count bound plus exact backwards links excludes cycles without
            // allocating a visited set inside the target process.
            if (output.visited >= registry.count) return false;
            if (output.visited >= maxRecords) {
                output.truncated = true;
                return true;
            }
            uint8_t raw[32]{};
            if ((node & 7) || !reader.copy(node, raw, sizeof(raw)) ||
                field<uint64_t>(raw, 0) != previous) return false;
            const uint32_t id = field<uint32_t>(raw, 0x10);
            const uint64_t next = field<uint64_t>(raw, 8);
            GmlRunnerInstanceRecord record;
            record.nodeAddress = node;
            if ((id & registry.mask) != bucket ||
                !ReadGmlRunnerObject(reader, base, field<uint64_t>(raw, 0x18), record.object) ||
                !record.object.isInstance || record.object.instanceNumber != id ||
                (next == 0 && node != ends[1]) || (next != 0 && node == ends[1])) return false;
            ++output.visited;
            if (!visitor(owner, record)) {
                output.truncated = true;
                return true;
            }
            previous = node;
            node = next;
        }
    }
    GmlRunnerInstanceRegistryView after;
    if (output.visited != registry.count ||
        !ReadGmlRunnerInstanceRegistry(reader, base, after) ||
        after.buckets != registry.buckets || after.mask != registry.mask ||
        after.count != registry.count) return false;
    output.complete = true;
    return true;
}
bool ReadGmlRunnerVariableMap(const GmlRunnerReader& reader, uint64_t address,
    GmlRunnerVariableMapView& output) noexcept {
    output = {};
    uint8_t raw[0x18]{};
    if (!reader.copy(address, raw, sizeof(raw))) return false;
    GmlRunnerVariableMapView value;
    value.address = address;
    value.capacity = field<uint32_t>(raw, 0);
    value.count = field<uint32_t>(raw, 4);
    value.mask = field<uint32_t>(raw, 8);
    value.entries = field<uint64_t>(raw, 0x10);
    if (!value.capacity || value.capacity > kGmlRunnerMaxObjectSlots ||
        (value.capacity & (value.capacity - 1)) || value.count > value.capacity ||
        value.mask != value.capacity - 1 || !range(value.entries, size_t(value.capacity) * 16)) return false;
    output = value;
    return true;
}
bool ReadGmlRunnerVariableEntry(const GmlRunnerReader& reader, const GmlRunnerVariableMapView& map,
    uint32_t slot, GmlRunnerVariableEntry& output) noexcept {
    output = {};
    uint8_t raw[16]{};
    if (!map.capacity || map.capacity > kGmlRunnerMaxObjectSlots || slot >= map.capacity ||
        !reader.copy(map.entries + uint64_t(slot) * 16, raw, sizeof(raw))) return false;
    const int32_t hash = field<int32_t>(raw, 12);
    if (hash <= 0) return true;
    const uint32_t id = field<uint32_t>(raw, 8);
    const uint64_t value = field<uint64_t>(raw, 0);
    if (uint32_t(hash) != ((id + 1) & 0x7fffffff) || !range(value, 16) || (value & 7)) return false;
    output = {value, id};
    return true;
}
bool ReadGmlRunnerString(const GmlRunnerReader& reader, uint64_t address,
    char* output, size_t capacity) noexcept {
    if (!output || capacity < 2 || capacity > 4096) return false;
    output[0] = 0;
    for (size_t i = 0; i < capacity; ++i) {
        char c = 0;
        if (!reader.copy(address + i, &c, 1)) { output[0] = 0; return false; }
        output[i] = c;
        if (!c) return true;
    }
    output[0] = 0;
    return false;
}
bool ReadGmlRunnerVariableName(const GmlRunnerReader& reader, uint64_t base,
    uint32_t runtimeId, char* output, size_t capacity) noexcept {
    if (output && capacity) output[0] = 0;
    if (runtimeId < 100000) return false;
    uint32_t counts[2]{};
    uint64_t names = 0;
    uint8_t modern = 0;
    if (!reader.copy(base + kNubby.modernNamesFlagRva, &modern, 1) || modern != 1 ||
        !reader.copy(base + kNubby.variableNameCountRva, counts, sizeof(counts)) ||
        !reader.copy(base + kNubby.variableNamesRva, &names, sizeof(names)) ||
        counts[0] > 262144 || counts[1] > counts[0] || runtimeId - 100000 >= counts[1]) return false;
    uint64_t string = 0;
    if (!reader.copy(names + uint64_t(runtimeId - 100000) * 8, &string, sizeof(string))) return false;
    return ReadGmlRunnerString(reader, string, output, capacity);
}
} // namespace ds
