#include "../src/Core/GameMakerRunner.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>

namespace {
constexpr uint64_t base = 0x140000000, heap = 0x10000000;
struct Memory {
    std::vector<uint8_t> image = std::vector<uint8_t>(0xa6f000);
    std::vector<uint8_t> data = std::vector<uint8_t>(0x40000);
    uint8_t* pointer(uint64_t at, size_t n) {
        if (at >= base && at - base <= image.size() && n <= image.size() - size_t(at - base))
            return image.data() + size_t(at - base);
        if (at >= heap && at - heap <= data.size() && n <= data.size() - size_t(at - heap))
            return data.data() + size_t(at - heap);
        return nullptr;
    }
    template<class T> void put(uint64_t at, T value) { auto p = pointer(at, sizeof(T)); assert(p); std::memcpy(p, &value, sizeof(T)); }
    void bytes(uint64_t at, const void* source, size_t n) { auto p = pointer(at, n); assert(p); std::memcpy(p, source, n); }
    static bool read(void* owner, uint64_t at, void* output, size_t n) {
        auto p = static_cast<Memory*>(owner)->pointer(at, n);
        if (!p) return false;
        std::memcpy(output, p, n);
        return true;
    }
};
}

int main() {
    using namespace ds;
    Memory m;
    GmlRunnerReader reader{&m, Memory::read};
    const auto& profile = NubbyGameMakerRunner();
    assert(MatchGameMakerRunner(profile.sha256) == &profile);
    assert(!MatchGameMakerRunner("5664918e"));
    GmlRunnerCapabilities capabilities;
    capabilities.supported=profile.capabilityMask;
    assert(!capabilities.supports(GmlRunnerCapability::InstructionStops));
    capabilities.runtimeVerified=true;
    assert(capabilities.supports(GmlRunnerCapability::InstructionStops));
    assert(capabilities.supports(GmlRunnerCapability::CallAwareSteps));
    assert(capabilities.supports(GmlRunnerCapability::NumericEdits));
    assert(!capabilities.supports(GmlRunnerCapability::OperandStackValues));
    assert(!capabilities.supports(GmlRunnerCapability::ComplexEdits));
    m.put<uint16_t>(base, 0x5a4d);
    m.put<uint32_t>(base + 0x3c, 0x80);
    m.put<uint32_t>(base + 0x80, 0x4550);
    m.put<uint16_t>(base + 0x84, 0x8664);
    m.put<uint16_t>(base + 0x98, 0x20b);
    m.put<uint32_t>(base + 0xd0, profile.imageSize);
    m.bytes(base + profile.interpreterEntry.rva, profile.interpreterEntry.original.data(), profile.interpreterEntry.byteCount);
    m.bytes(base + profile.instructionDispatch.rva, profile.instructionDispatch.original.data(), profile.instructionDispatch.byteCount);
    m.bytes(base + profile.instanceConstructor.rva, profile.instanceConstructor.original.data(), profile.instanceConstructor.byteCount);
    m.bytes(base + profile.instanceDestructor.rva, profile.instanceDestructor.original.data(), profile.instanceDestructor.byteCount);
    m.put<uint8_t>(base + profile.modernNamesFlagRva, 1);
    assert(ValidateGmlRunnerImage(reader, base, profile));
    m.put<uint8_t>(base + profile.instructionDispatch.rva, 0xcc);
    assert(!ValidateGmlRunnerImage(reader, base, profile));
    m.put<uint8_t>(base + profile.instructionDispatch.rva, 0x89);
    m.put<uint64_t>(base + profile.debuggerObjectRva, heap);
    assert(!ValidateGmlRunnerImage(reader, base, profile));
    m.put<uint64_t>(base + profile.debuggerObjectRva, 0);

    constexpr uint64_t code = heap + 0x1000, caller = heap + 0x1200;
    constexpr uint64_t blob = heap + 0x2000, bytecode = heap + 0x3000, context = heap + 0x4000;
    constexpr uint64_t object = heap + 0x5000, mapAddress = heap + 0x6000, entries = heap + 0x7000;
    constexpr uint64_t value = heap + 0x8000, name = heap + 0x9000, names = heap + 0xa000;
    constexpr uint64_t buffer = heap + 0x10000, end = buffer + 0x8000;
    constexpr uint64_t anchor = end - 0x100, parentAnchor = end - 0x88, arguments = end - 0x10;
    for (uint64_t c : {code, caller}) {
        m.put<uint64_t>(c, base + 0x633800);
        m.put<uint32_t>(c + 0x10, 1);
        m.put<uint64_t>(c + 0x68, blob);
        m.put<uint64_t>(c + 0x80, name);
    }
    m.put<uint32_t>(code + 0x88, 1);
    m.put<uint32_t>(code + 0x9c, 4);
    m.put<uint32_t>(blob + 8, 64);
    m.put<uint64_t>(blob + 0x18, bytecode);
    m.bytes(name, "_size", 6);
    GmlRunnerCodeView codeView;
    assert(ReadGmlRunnerCode(reader, base, code, codeView) && codeView.codeIndex == 1 && codeView.entryOffset == 4);
    m.put<uint64_t>(code + 0x90, heap);
    assert(!ReadGmlRunnerCode(reader, base, code, codeView)); // YYC descriptor
    m.put<uint64_t>(code + 0x90, 0);
    m.put<uint32_t>(blob + 8, UINT32_MAX);
    assert(!ReadGmlRunnerCode(reader, base, code, codeView));
    m.put<uint32_t>(blob + 8, 64);

    m.put<uint64_t>(context + 0x10, buffer);
    m.put<uint64_t>(context + 0x20, object);
    m.put<uint64_t>(context + 0x28, object);
    m.put<uint64_t>(context + 0x38, code);
    m.put<uint64_t>(context + 0x40, arguments);
    m.put<uint32_t>(context + 0x48, 1);
    m.put<uint64_t>(context + 0x50, bytecode);
    m.put<uint64_t>(context + 0x58, anchor);
    m.put<uint64_t>(context + 0x60, blob);
    m.put<uint32_t>(context + 0x88, 0x8000);
    m.put<uint32_t>(context + 0x8c, 4);
    m.put<uint32_t>(context + 0x94, 1);
    m.put<uint32_t>(context + 0x98, 64);
    m.put<uint32_t>(anchor, kGmlRunnerFrameMagic);
    m.put<uint32_t>(anchor + 4, 16);
    m.put<uint32_t>(anchor + 0x0c, 1);
    m.put<uint32_t>(anchor + 0x10, 0x88);
    m.put<uint32_t>(anchor + 0x18, 0x10);
    m.put<uint64_t>(anchor + 0x30, caller);
    m.put<uint64_t>(anchor + 0x38, blob);
    m.put<uint32_t>(parentAnchor, kGmlRunnerFrameMagic);
    GmlRunnerContextView contextView;
    assert(ReadGmlRunnerContext(reader, base, context, 4, anchor - 4, contextView));
    assert(!ReadGmlRunnerContext(reader, base, context, 8, anchor, contextView)); // stale PC
    assert(!ReadGmlRunnerContext(reader, base, context, 4, buffer - 4, contextView));
    assert(ReadGmlRunnerContext(reader, base, context, 4, anchor - 4, contextView));
    GmlRunnerSavedFrameView saved;
    assert(ReadGmlRunnerSavedFrame(reader, base, contextView, anchor, saved));
    assert(saved.previousAnchor == parentAnchor && saved.returnOffset == 16 && saved.arguments == arguments);
    m.put<uint32_t>(anchor + 0x10, 0x100);
    assert(!ReadGmlRunnerSavedFrame(reader, base, contextView, anchor, saved)); // cyclic anchor
    m.put<uint32_t>(anchor + 0x10, UINT32_MAX);
    assert(!ReadGmlRunnerSavedFrame(reader, base, contextView, anchor, saved)); // root sentinel

    m.put<uint64_t>(object, base + profile.instanceVtableRva);
    m.put<uint32_t>(object + 0x7c, 1);
    m.put<uint32_t>(object + 0xbc, 100001);
    m.put<uint32_t>(object + 0xc0, 203);
    m.put<uint64_t>(object + 0x48, mapAddress);
    GmlRunnerObjectView objectView;
    assert(ReadGmlRunnerObject(reader, base, object, objectView) && objectView.isInstance && objectView.objectIndex == 203);
    m.put<uint64_t>(object, base + profile.objectVtableRva);
    m.put<uint32_t>(object + 0x7c, 0);
    assert(ReadGmlRunnerObject(reader, base, object, objectView) && !objectView.isInstance && objectView.objectIndex == UINT32_MAX);
    m.put<uint32_t>(mapAddress, 8);
    m.put<uint32_t>(mapAddress + 4, 1);
    m.put<uint32_t>(mapAddress + 8, 7);
    m.put<uint64_t>(mapAddress + 0x10, entries);
    m.put<uint64_t>(entries, value);
    m.put<uint32_t>(entries + 8, 100001);
    m.put<uint32_t>(entries + 12, 100002);
    GmlRunnerVariableMapView map;
    GmlRunnerVariableEntry entry;
    assert(ReadGmlRunnerVariableMap(reader, mapAddress, map));
    assert(ReadGmlRunnerVariableEntry(reader, map, 0, entry) && entry.valueAddress == value);
    assert(ReadGmlRunnerVariableEntry(reader, map, 1, entry) && !entry.valueAddress);
    assert(!ReadGmlRunnerVariableEntry(reader, map, 8, entry));
    m.put<uint32_t>(entries + 12, 123);
    assert(!ReadGmlRunnerVariableEntry(reader, map, 0, entry));
    m.put<uint32_t>(mapAddress + 8, 15);
    assert(!ReadGmlRunnerVariableMap(reader, mapAddress, map));

    m.put<uint32_t>(base + profile.variableNameCountRva, 3);
    m.put<uint32_t>(base + profile.variableNameCountRva + 4, 2);
    m.put<uint64_t>(base + profile.variableNamesRva, names);
    m.put<uint64_t>(names + 8, name);
    char text[16];
    assert(ReadGmlRunnerVariableName(reader, base, 100001, text, sizeof(text)) && std::strcmp(text, "_size") == 0);
    assert(!ReadGmlRunnerVariableName(reader, base, 100002, text, sizeof(text))); // dynamic extent
    assert(!ReadGmlRunnerString(reader, name, text, 4)); // truncated, never fabricated
    assert(!reader.copy(UINT64_MAX, text, 4));

    // Real registry shape: colliding IDs in a doubly linked bucket, plus a
    // separate bucket. Fixtures stress completeness rather than only samples.
    constexpr uint64_t buckets = heap + 0x20000, node0 = heap + 0x21000;
    constexpr uint64_t node1 = node0 + 0x40, node2 = node0 + 0x80;
    constexpr uint64_t instance0 = heap + 0x22000, instance1 = instance0 + 0x300;
    constexpr uint64_t instance2 = instance0 + 0x600;
    const uint64_t registry = base + profile.instanceRegistryRva;
    m.put<uint64_t>(registry, buckets);
    m.put<uint32_t>(registry + 8, 3);
    m.put<uint32_t>(registry + 12, 3);
    m.put<uint64_t>(buckets + 16, node0);
    m.put<uint64_t>(buckets + 24, node1);
    m.put<uint64_t>(buckets + 32, node2);
    m.put<uint64_t>(buckets + 40, node2);
    const uint64_t nodes[] = {node0, node1, node2};
    const uint64_t instances[] = {instance0, instance1, instance2};
    const uint32_t ids[] = {100001, 100005, 100002};
    for (int i = 0; i < 3; ++i) {
        m.put<uint64_t>(nodes[i] + 0x18, instances[i]);
        m.put<uint32_t>(nodes[i] + 0x10, ids[i]);
        m.put<uint64_t>(instances[i], base + profile.instanceVtableRva);
        m.put<uint32_t>(instances[i] + 0x7c, 1);
        m.put<uint32_t>(instances[i] + 0xbc, ids[i]);
        m.put<uint32_t>(instances[i] + 0xc0, 203 + i);
    }
    m.put<uint64_t>(node0 + 8, node1);
    m.put<uint64_t>(node1, node0);
    std::vector<GmlRunnerInstanceRecord> records;
    auto collect = [](void* owner, const GmlRunnerInstanceRecord& record) {
        static_cast<std::vector<GmlRunnerInstanceRecord>*>(owner)->push_back(record);
        return true;
    };
    GmlRunnerInstanceEnumeration enumeration;
    assert(EnumerateGmlRunnerInstances(reader, base, 16, collect, &records, enumeration));
    assert(enumeration.complete && !enumeration.truncated && enumeration.visited == 3 && records.size() == 3);
    assert(records[1].object.address == instance1 && records[2].object.objectIndex == 205);
    records.clear();
    assert(EnumerateGmlRunnerInstances(reader, base, 1, collect, &records, enumeration));
    assert(!enumeration.complete && enumeration.truncated && enumeration.visited == 1);
    m.put<uint64_t>(node1, 0); // broken backwards link
    assert(!EnumerateGmlRunnerInstances(reader, base, 16, collect, &records, enumeration));
    m.put<uint64_t>(node1, node0);
    m.put<uint64_t>(node1 + 8, node0); // cycle, including false tail
    assert(!EnumerateGmlRunnerInstances(reader, base, 16, collect, &records, enumeration));
    m.put<uint64_t>(node1 + 8, 0);
    m.put<uint32_t>(registry + 12, 4); // inflated count cannot claim completeness
    assert(!EnumerateGmlRunnerInstances(reader, base, 16, collect, &records, enumeration));
    m.put<uint32_t>(registry + 12, 3);
    m.put<uint32_t>(instance1 + 0xbc, 123); // stale/reused instance address
    assert(!EnumerateGmlRunnerInstances(reader, base, 16, collect, &records, enumeration));
    m.put<uint32_t>(instance1 + 0xbc, ids[1]);
    m.put<uint64_t>(buckets + 24, node0); // advertised tail disagrees
    assert(!EnumerateGmlRunnerInstances(reader, base, 16, collect, &records, enumeration));
    m.put<uint64_t>(buckets + 24, node1);
    m.put<uint32_t>(registry + 8, UINT32_MAX); // no unbounded traversal
    assert(!EnumerateGmlRunnerInstances(reader, base, 16, collect, &records, enumeration));
    std::cout << "GameMaker runner adapter tests passed\n";
}
