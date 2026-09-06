#include "../src/Core/GameMakerInspection.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

namespace {
using namespace ds;
constexpr uint64_t base = 0x140000000, heap = 0x10000000;
constexpr uint64_t table = heap + 0x10000, buckets = heap + 0x11000;
constexpr uint64_t objects[] = {heap + 0x1000, heap + 0x2000, heap + 0x3000};
constexpr uint64_t nodes[] = {heap + 0x12000, heap + 0x12040, heap + 0x12080};
constexpr uint32_t numbers[] = {100001, 100002, 100005};
constexpr uint64_t names = heap + 0x13000;
struct Memory {
    std::vector<uint8_t> image = std::vector<uint8_t>(0xa6f000);
    std::vector<uint8_t> data = std::vector<uint8_t>(0x40000);
    bool changeCommit = false;
    uint32_t tableReads = 0;
    uint8_t* pointer(uint64_t at, size_t n) {
        if (at >= base && at - base <= image.size() && n <= image.size() - size_t(at - base))
            return image.data() + size_t(at - base);
        if (at >= heap && at - heap <= data.size() && n <= data.size() - size_t(at - heap))
            return data.data() + size_t(at - heap);
        return nullptr;
    }
    template<class T> void put(uint64_t at, T value) {
        auto* p = pointer(at, sizeof(value)); assert(p); std::memcpy(p, &value, sizeof(value));
    }
    void bytes(uint64_t at, const void* dataValue, size_t n) {
        auto* p = pointer(at, n); assert(p); std::memcpy(p, dataValue, n);
    }
    static bool read(void* owner, uint64_t at, void* output, size_t n) {
        auto& m = *static_cast<Memory*>(owner);
        if (at == table && n == 8 * sizeof(GmlHelperInstanceLifetime) &&
            ++m.tableReads == 2 && m.changeCommit) m.put<uint64_t>(table + 16, 4);
        auto* p = m.pointer(at, n);
        if (!p) return false;
        std::memcpy(output, p, n);
        return true;
    }
    GmlRunnerReader reader() { return {this, read}; }
    static uint64_t map(int i) { return objects[i] + 0x300; }
    static uint64_t entries(int i) { return objects[i] + 0x400; }
    static uint64_t value(int i, int j = 0) { return objects[i] + 0x500 + uint64_t(j) * 16; }
    Memory() {
        const auto& profile = NubbyGameMakerRunner();
        put<uint64_t>(base + profile.instanceRegistryRva, buckets);
        put<uint32_t>(base + profile.instanceRegistryRva + 8, 3);
        put<uint32_t>(base + profile.instanceRegistryRva + 12, 3);
        put<uint64_t>(buckets + 16, nodes[0]); put<uint64_t>(buckets + 24, nodes[2]);
        put<uint64_t>(buckets + 32, nodes[1]); put<uint64_t>(buckets + 40, nodes[1]);
        put<uint64_t>(nodes[0] + 8, nodes[2]); put<uint64_t>(nodes[2], nodes[0]);
        for (int i = 0; i < 3; ++i) {
            put<uint32_t>(nodes[i] + 0x10, numbers[i]);
            put<uint64_t>(nodes[i] + 0x18, objects[i]);
            put<uint64_t>(objects[i], base + profile.instanceVtableRva);
            put<uint64_t>(objects[i] + 0x48, map(i));
            put<uint32_t>(objects[i] + 0x7c, 1);
            put<uint32_t>(objects[i] + 0xbc, numbers[i]);
            put<uint32_t>(objects[i] + 0xc0, 203 + i);
            put<GmlHelperInstanceLifetime>(table + uint64_t(i) * 24, {objects[i], uint64_t(1001 + i), 2});
            put<uint32_t>(map(i), 4); put<uint32_t>(map(i) + 4, 2); put<uint32_t>(map(i) + 8, 3);
            put<uint64_t>(map(i) + 16, entries(i));
            for (int j = 0; j < 2; ++j) {
                put<uint64_t>(entries(i) + uint64_t(j) * 16, value(i, j));
                put<uint32_t>(entries(i) + uint64_t(j) * 16 + 8, 100000 + j);
                put<uint32_t>(entries(i) + uint64_t(j) * 16 + 12, 100001 + j);
                put<GmlRValue>(value(i, j), {j ? 0x3ff0000000000000ULL : 0x4024000000000000ULL, 0, j ? 13u : 0u});
            }
        }
        put<uint8_t>(base + profile.modernNamesFlagRva, 1);
        put<uint64_t>(base + profile.variableNamesRva, names);
        put<uint32_t>(base + profile.variableNameCountRva, 3);
        put<uint32_t>(base + profile.variableNameCountRva + 4, 3);
        const char* labels[] = {"score", "health", "opaque"};
        for (int i = 0; i < 3; ++i) {
            const auto at = names + 0x100 + uint64_t(i) * 0x40;
            put<uint64_t>(names + uint64_t(i) * 8, at);
            bytes(at, labels[i], std::strlen(labels[i]) + 1);
        }
    }
};
std::unique_ptr<GmlHelperStop> initialStop() {
    auto stop = std::make_unique<GmlHelperStop>();
    stop->nonce = 111; stop->identity = {12, 13, 1, 2, 3}; stop->adapterId = kGmlNubbyAdapterId;
    stop->location = {1234, 0, 4}; stop->reason = GmlStopReason::Pause;
    stop->frameCount = 1; stop->frames[0].frameId = 1;
    stop->numericSlotCount = 2;
    stop->numericSlots[0].scope = GmlVariableScope::Global;
    stop->numericSlots[0].address = heap + 0x20000;
    stop->numericSlots[1].scope = GmlVariableScope::FrameLocal;
    stop->numericSlots[1].address = heap + 0x20010;
    return stop;
}
bool inspect(Memory& memory, GmlHelperStop& stop, uint32_t object, uint64_t instance = 0) {
    return InspectGmlFrozenInstances(memory.reader(), base, table, 8, object, instance, stop);
}
const GmlHelperInstance& instance(const GmlHelperStop& stop, uint64_t token) {
    for (uint32_t i = 0; i < stop.instanceCount; ++i) if (stop.instances[i].instanceId == token) return stop.instances[i];
    assert(false); return stop.instances[0];
}
const GmlHelperNumericSlot& slot(const GmlHelperStop& stop, uint64_t token, uint32_t id = 100000) {
    for (uint32_t i = 0; i < stop.numericSlotCount; ++i)
        if (stop.numericSlots[i].instanceId == token && stop.numericSlots[i].runtimeVariableId == id) return stop.numericSlots[i];
    assert(false); return stop.numericSlots[0];
}
}

int main() {
    using namespace ds;
    Memory m;
    auto stop = initialStop();
    assert(inspect(m, *stop, 203));
    assert(stop->instancesComplete && stop->instanceCount == 3 && stop->instanceVariablesComplete);
    assert(stop->selectedObjectIndex == 203 && !stop->selectedInstanceId && stop->numericSlotCount == 4);
    assert(stop->numericSlots[0].scope == GmlVariableScope::Global && stop->numericSlots[1].scope == GmlVariableScope::FrameLocal);
    assert(instance(*stop, 1001).variablesAvailability == GmlValueAvailability::Available);
    assert(instance(*stop, 1002).variablesAvailability == GmlValueAvailability::Unavailable);
    assert(std::strcmp(slot(*stop, 1001).name, "score") == 0 && slot(*stop, 1001).nameLength == 5);
    assert(slot(*stop, 1001, 100001).kind == GmlNumericKind::Boolean);
    assert(ValidateGmlFrozenInstanceSlotOwnership(m.reader(), base, table, 8, *stop, slot(*stop, 1001)));

    // Selecting another domain retains and recertifies prior domains, allowing
    // several persistent object watches in one frozen snapshot.
    assert(inspect(m, *stop, 204));
    assert(stop->numericSlotCount == 6 && stop->selectedObjectIndex == 204);
    assert(instance(*stop, 1001).variablesAvailability == GmlValueAvailability::Available);
    assert(instance(*stop, 1002).variablesAvailability == GmlValueAvailability::Available);
    assert(inspect(m, *stop, 204) && stop->numericSlotCount == 6); // no duplicates
    assert(inspect(m, *stop, kGmlNoCodeIndex, 1003));
    assert(stop->numericSlotCount == 8 && stop->selectedInstanceId == 1003 && stop->instanceVariablesComplete);

    // A new stop can rebind an object watch after a restart with a new token.
    m.put<GmlHelperInstanceLifetime>(table, {objects[0], 2001, 4});
    const auto oldCount = stop->numericSlotCount;
    assert(!inspect(m, *stop, 203) && stop->numericSlotCount == oldCount);
    assert(!ValidateGmlFrozenInstanceSlotOwnership(m.reader(), base, table, 8, *stop, slot(*stop, 1001)));
    auto fresh = initialStop(); fresh->identity.stopSequence = 4;
    assert(inspect(m, *fresh, 203) && slot(*fresh, 2001).ownerObject == objects[0]);

    // A committed identity does not justify a moved canonical member pointer.
    const auto oldSlot = slot(*fresh, 2001);
    m.put<uint64_t>(Memory::entries(0), Memory::value(0, 2));
    m.put<GmlRValue>(Memory::value(0, 2), oldSlot.value);
    assert(!ValidateGmlFrozenInstanceSlotOwnership(m.reader(), base, table, 8, *fresh, oldSlot));
    assert(inspect(m, *fresh, 204)); // retained object 203 is refreshed as well
    assert(slot(*fresh, 2001).address == Memory::value(0, 2));

    m.put<uint64_t>(table + 16, 5); // interrupted commit
    assert(!inspect(m, *fresh, 203));
    m.put<uint64_t>(table + 16, 4);
    m.put<GmlHelperInstanceLifetime>(table + 3 * 24, {objects[0], 9999, 2}); // duplicate address
    assert(!inspect(m, *fresh, 203));
    m.put<GmlHelperInstanceLifetime>(table + 3 * 24, {});
    m.put<uint64_t>(table + 24 + 8, 2001); // duplicate live token
    assert(!inspect(m, *fresh, 203));
    m.put<uint64_t>(table + 24 + 8, 1002);
    m.put<uint64_t>(table + 24 + 8, 0); // retired but still registered is unsafe
    assert(!inspect(m, *fresh, 203));
    m.put<uint64_t>(table + 24 + 8, 1002);
    assert(!inspect(m, *fresh, 203, 2001)); // conflicting selectors

    // Complete object selection includes every matching allocation, so the UI
    // can reject uniqueness even when only one has a numeric variable.
    m.put<uint32_t>(objects[2] + 0xc0, 203);
    auto multiple = initialStop();
    assert(inspect(m, *multiple, 203));
    assert(slot(*multiple, 2001).objectIndex == 203 && slot(*multiple, 1003).objectIndex == 203);
    assert(multiple->numericSlotCount == 6);
    m.put<GmlRValue>(Memory::value(2), {0, 0, 1}); // nonnumeric first field
    assert(inspect(m, *multiple, 203));
    assert(multiple->numericSlotCount == 5 && multiple->instanceVariablesComplete);
    uint32_t matchingInstances = 0;
    for (uint32_t i = 0; i < multiple->instanceCount; ++i) matchingInstances += multiple->instances[i].objectIndex == 203;
    assert(matchingInstances == 2); // variable-row count cannot prove unique object

    // Unknown dynamic names keep the domain visibly incomplete.
    m.put<uint32_t>(Memory::entries(0) + 8, 100003);
    m.put<uint32_t>(Memory::entries(0) + 12, 100004);
    auto unnamed = initialStop();
    assert(inspect(m, *unnamed, 203));
    assert(!unnamed->instanceVariablesComplete && slot(*unnamed, 2001, 100003).nameLength == 0);
    assert(instance(*unnamed, 2001).variablesAvailability == GmlValueAvailability::Unavailable);

    // Space exhaustion preserves existing globals/locals and reports truncation.
    auto full = initialStop(); full->numericSlotCount = kGmlMaxNumericSlots;
    assert(inspect(m, *full, 204));
    assert(full->numericSlotCount == kGmlMaxNumericSlots && !full->instanceVariablesComplete);
    assert(instance(*full, 1002).variablesAvailability == GmlValueAvailability::Truncated);

    Memory racing;
    racing.changeCommit = true;
    auto changed = initialStop();
    assert(!inspect(racing, *changed, 203));
    assert(changed->numericSlotCount == 2 && !changed->instanceCount); // transactional failure
    std::cout << "GameMaker frozen instance inspection tests passed\n";
}
