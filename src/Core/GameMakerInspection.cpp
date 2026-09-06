#include "GameMakerInspection.h"
#include <algorithm>
#include <cstring>
#include <memory>
#include <new>
#include <vector>

namespace ds {
namespace {
constexpr uint32_t kMaxInspectedMapEntries = 131072;
bool fail(std::string* error, const char* message) {
    if (error) *error = message;
    return false;
}
bool instanceScope(GmlVariableScope scope) {
    return scope == GmlVariableScope::SessionInstance || scope == GmlVariableScope::UniqueObject;
}
bool stopShape(const GmlHelperStop& stop) {
    const auto& id = stop.identity;
    return stop.magic == kGmlProtocolMagic && stop.version == kGmlProtocolVersion &&
        stop.byteSize == sizeof(stop) && stop.nonce && id.pid && id.tid && id.sessionGeneration &&
        id.helperGeneration && id.stopSequence && stop.adapterId == kGmlNubbyAdapterId &&
        stop.frameCount <= kGmlMaxFrames && stop.numericSlotCount <= kGmlMaxNumericSlots &&
        stop.instanceCount <= kGmlMaxInstances;
}
struct FrozenRegistry {
    std::vector<GmlHelperInstanceLifetime> rawLifetimes, lifetimes;
    std::vector<GmlRunnerInstanceRecord> records;
    GmlRunnerInstanceEnumeration enumeration;
    const GmlHelperInstanceLifetime* lifetime(uint64_t address) const {
        auto it = std::lower_bound(lifetimes.begin(), lifetimes.end(), address,
            [](const auto& entry, uint64_t key) { return entry.objectAddress < key; });
        return it != lifetimes.end() && it->objectAddress == address ? &*it : nullptr;
    }
    const GmlRunnerInstanceRecord* instance(uint64_t address) const {
        auto it = std::lower_bound(records.begin(), records.end(), address,
            [](const auto& entry, uint64_t key) { return entry.object.address < key; });
        return it != records.end() && it->object.address == address ? &*it : nullptr;
    }
};
bool sameLifetimes(const GmlRunnerReader& reader, uint64_t address,
    const FrozenRegistry& frozen, std::string* error) {
    std::vector<GmlHelperInstanceLifetime> after(frozen.rawLifetimes.size());
    const size_t bytes = after.size() * sizeof(after[0]);
    if (!reader.copy(address, after.data(), bytes) ||
        std::memcmp(after.data(), frozen.rawLifetimes.data(), bytes))
        return fail(error, "Instance lifetime table changed or became unreadable during the held stop");
    return true;
}
bool loadFrozen(const GmlRunnerReader& reader, uint64_t base, uint64_t tableAddress,
    uint32_t capacity, FrozenRegistry& output, std::string* error) {
    if (!capacity || capacity > kGmlMaxInstanceLifetimes || (tableAddress & 7))
        return fail(error, "Invalid instance lifetime table bounds");
    output.rawLifetimes.resize(capacity);
    if (!reader.copy(tableAddress, output.rawLifetimes.data(), size_t(capacity) * sizeof(GmlHelperInstanceLifetime)))
        return fail(error, "Cannot read the helper instance lifetime table");
    output.lifetimes.reserve(capacity);
    std::vector<uint64_t> tokens;
    tokens.reserve(capacity);
    for (const auto& entry : output.rawLifetimes) {
        if (!entry.sequence) {
            if (entry.objectAddress || entry.instanceId)
                return fail(error, "An instance lifetime entry has not been committed");
            continue;
        }
        if ((entry.sequence & 1) || entry.objectAddress < 0x10000 ||
            entry.objectAddress > 0x00007fffffffffffULL || (entry.objectAddress & 7))
            return fail(error, "An instance lifetime transition is incomplete at this stop");
        output.lifetimes.push_back(entry);
        if (entry.instanceId) tokens.push_back(entry.instanceId);
    }
    std::sort(output.lifetimes.begin(), output.lifetimes.end(),
        [](const auto& a, const auto& b) { return a.objectAddress < b.objectAddress; });
    for (size_t i = 1; i < output.lifetimes.size(); ++i)
        if (output.lifetimes[i - 1].objectAddress == output.lifetimes[i].objectAddress)
            return fail(error, "Duplicate object addresses in the helper lifetime table");
    std::sort(tokens.begin(), tokens.end());
    if (std::adjacent_find(tokens.begin(), tokens.end()) != tokens.end())
        return fail(error, "Duplicate live allocation tokens in the helper lifetime table");
    output.records.reserve(kGmlMaxInstances);
    auto collect = [](void* owner, const GmlRunnerInstanceRecord& record) {
        static_cast<std::vector<GmlRunnerInstanceRecord>*>(owner)->push_back(record);
        return true;
    };
    if (!EnumerateGmlRunnerInstances(reader, base, kGmlMaxInstances, collect, &output.records, output.enumeration))
        return fail(error, "Instance registry links, counts, or object identities are inconsistent");
    std::sort(output.records.begin(), output.records.end(),
        [](const auto& a, const auto& b) { return a.object.address < b.object.address; });
    for (size_t i = 0; i < output.records.size(); ++i) {
        const auto& record = output.records[i];
        if (i && output.records[i - 1].object.address == record.object.address)
            return fail(error, "An allocation appears more than once in the instance registry");
        const auto* lifetime = output.lifetime(record.object.address);
        if (!lifetime || !lifetime->instanceId)
            return fail(error, "The helper has no committed lifetime for a registered instance");
    }
    return true;
}
bool matches(const FrozenRegistry& frozen, uint64_t address, uint64_t token,
    uint32_t number, uint32_t objectIndex) {
    const auto* record = frozen.instance(address);
    const auto* lifetime = frozen.lifetime(address);
    return record && lifetime && token && lifetime->instanceId == token &&
        record->object.instanceNumber == number && record->object.objectIndex == objectIndex;
}
GmlNumericKind numericKind(uint32_t tag) {
    switch (tag) {
    case 0: return GmlNumericKind::Real;
    case 7: return GmlNumericKind::Int32;
    case 10: return GmlNumericKind::Int64;
    case 13: return GmlNumericKind::Boolean;
    default: return GmlNumericKind::None;
    }
}
bool mapUnchanged(const GmlRunnerReader& reader, uint64_t base,
    const GmlRunnerObjectView& object, const GmlRunnerVariableMapView& map) {
    GmlRunnerObjectView afterObject;
    GmlRunnerVariableMapView afterMap;
    return ReadGmlRunnerObject(reader, base, object.address, afterObject) &&
        afterObject.isInstance && afterObject.instanceNumber == object.instanceNumber &&
        afterObject.objectIndex == object.objectIndex && afterObject.variableMap == object.variableMap &&
        ReadGmlRunnerVariableMap(reader, object.variableMap, afterMap) &&
        afterMap.entries == map.entries && afterMap.capacity == map.capacity &&
        afterMap.count == map.count && afterMap.mask == map.mask;
}
GmlValueAvailability appendInstance(const GmlRunnerReader& reader, uint64_t base,
    const GmlRunnerObjectView& object, uint64_t token, uint32_t& budget, GmlHelperStop& stop) {
    GmlRunnerVariableMapView map;
    if (!object.variableMap || !ReadGmlRunnerVariableMap(reader, object.variableMap, map))
        return GmlValueAvailability::Unavailable;
    uint32_t found = 0;
    bool complete = true;
    for (uint32_t i = 0; i < map.capacity; ++i) {
        if (!budget) return GmlValueAvailability::Truncated;
        --budget;
        GmlRunnerVariableEntry entry;
        if (!ReadGmlRunnerVariableEntry(reader, map, i, entry)) return GmlValueAvailability::Unavailable;
        if (!entry.valueAddress) continue;
        ++found;
        GmlRValue value;
        if (!reader.copy(entry.valueAddress, &value, sizeof(value))) {
            complete = false;
            continue;
        }
        const auto kind = numericKind(value.typeTag);
        if (kind == GmlNumericKind::None) continue;
        bool duplicate = false;
        for (uint32_t j = 0; j < stop.numericSlotCount; ++j)
            duplicate = duplicate || (stop.numericSlots[j].address == entry.valueAddress &&
                stop.numericSlots[j].scope == GmlVariableScope::SessionInstance);
        if (duplicate) { complete = false; continue; }
        if (stop.numericSlotCount == kGmlMaxNumericSlots) return GmlValueAvailability::Truncated;
        auto& slot = stop.numericSlots[stop.numericSlotCount++];
        slot = {};
        slot.address = entry.valueAddress;
        slot.instanceId = token;
        slot.value = value;
        slot.variableIndex = kGmlNoCodeIndex;
        slot.kind = kind;
        slot.writable = 1;
        slot.storage = GmlSlotStorage::Canonical;
        slot.availability = GmlValueAvailability::Available;
        slot.runtimeVariableId = entry.runtimeId;
        slot.scope = GmlVariableScope::SessionInstance;
        slot.objectIndex = object.objectIndex;
        slot.ownerObject = object.address;
        slot.runtimeInstanceNumber = object.instanceNumber;
        if (ReadGmlRunnerVariableName(reader, base, entry.runtimeId, slot.name, sizeof(slot.name)))
            slot.nameLength = static_cast<uint32_t>(std::strlen(slot.name));
        else complete = false;
    }
    if (found != map.count || !mapUnchanged(reader, base, object, map)) complete = false;
    return complete ? GmlValueAvailability::Available : GmlValueAvailability::Unavailable;
}
} // namespace

bool InspectGmlFrozenInstances(const GmlRunnerReader& reader, uint64_t base,
    uint64_t lifetimesAddress, uint32_t capacity, uint32_t selectedObjectIndex,
    uint64_t selectedInstanceId, GmlHelperStop& stop, std::string* error) {
    if (error) error->clear();
    if (!stopShape(stop) || (selectedInstanceId && selectedObjectIndex != kGmlNoCodeIndex))
        return fail(error, "Invalid held GML stop or conflicting instance selectors");
    try {
        FrozenRegistry frozen;
        if (!loadFrozen(reader, base, lifetimesAddress, capacity, frozen, error)) return false;
        // Old helper projections may predate the Win32 event by several native
        // instructions. Every old instance identity must survive that interval.
        for (uint32_t i = 0; i < stop.instanceCount; ++i) {
            const auto& old = stop.instances[i];
            if (!matches(frozen, old.objectAddress, old.instanceId, old.runtimeInstanceNumber, old.objectIndex))
                return fail(error, "A captured instance was removed or recreated before this stop");
        }
        for (uint32_t i = 0; i < stop.numericSlotCount; ++i) {
            const auto& old = stop.numericSlots[i];
            if (instanceScope(old.scope) && !matches(frozen, old.ownerObject, old.instanceId,
                    old.runtimeInstanceNumber, old.objectIndex))
                return fail(error, "A captured numeric owner no longer has the same instance lifetime");
        }
        auto next = std::make_unique<GmlHelperStop>(stop);
        next->selectedObjectIndex = selectedObjectIndex;
        next->selectedInstanceId = selectedInstanceId;
        next->selectionReserved = 0;
        next->instanceCount = static_cast<uint32_t>(frozen.records.size());
        next->instancesComplete = frozen.enumeration.complete ? 1u : 0u;
        next->instanceVariablesComplete = 0;
        next->numericSlotCount = 0;
        for (uint32_t i = 0; i < stop.numericSlotCount; ++i)
            if (!instanceScope(stop.numericSlots[i].scope))
                next->numericSlots[next->numericSlotCount++] = stop.numericSlots[i];
        std::vector<uint32_t> selected, previous;
        for (uint32_t i = 0; i < next->instanceCount; ++i) {
            const auto& object = frozen.records[i].object;
            const auto token = frozen.lifetime(object.address)->instanceId;
            auto& instance = next->instances[i];
            instance = {token, object.address, object.instanceNumber, object.objectIndex};
            const bool requested = selectedInstanceId ? selectedInstanceId == token :
                selectedObjectIndex != kGmlNoCodeIndex && selectedObjectIndex == object.objectIndex;
            bool retained = false;
            for (uint32_t j = 0; j < stop.instanceCount; ++j)
                retained = retained || (stop.instances[j].instanceId == token &&
                    stop.instances[j].variablesAvailability != GmlValueAvailability::Unavailable);
            for (uint32_t j = 0; j < stop.numericSlotCount; ++j)
                retained = retained || (instanceScope(stop.numericSlots[j].scope) &&
                    stop.numericSlots[j].instanceId == token);
            if (requested) selected.push_back(i);
            else if (retained) previous.push_back(i);
        }
        // Prior inspected domains are reprojected as well: token equality alone
        // does not prove that the old variable map or value addresses survived.
        uint32_t budget = kMaxInspectedMapEntries;
        for (const auto* list : {&selected, &previous}) for (const uint32_t i : *list)
            next->instances[i].variablesAvailability = appendInstance(reader, base,
                frozen.records[i].object, next->instances[i].instanceId, budget, *next);
        for (uint32_t i = 0; i < next->frameCount; ++i) {
            auto& frame = next->frames[i];
            if (!frame.instanceId) continue;
            frame.selfAvailability = GmlValueAvailability::Unavailable;
            for (uint32_t j = 0; j < next->instanceCount; ++j)
                if (next->instances[j].instanceId == frame.instanceId &&
                    next->instances[j].objectAddress == frame.selfObject)
                    frame.selfAvailability = next->instances[j].variablesAvailability;
        }
        bool selectedComplete = selectedInstanceId || selectedObjectIndex != kGmlNoCodeIndex;
        for (const uint32_t i : selected)
            selectedComplete = selectedComplete && next->instances[i].variablesAvailability == GmlValueAvailability::Available;
        next->instanceVariablesComplete = selectedComplete && next->instancesComplete ? 1u : 0u;
        if (!sameLifetimes(reader, lifetimesAddress, frozen, error)) return false;
        stop = *next;
        return true;
    } catch (const std::bad_alloc&) {
        return fail(error, "Insufficient host memory for bounded instance inspection");
    }
}

bool ValidateGmlFrozenInstanceSlotOwnership(const GmlRunnerReader& reader, uint64_t base,
    uint64_t lifetimesAddress, uint32_t capacity, const GmlHelperStop& stop,
    const GmlHelperNumericSlot& slot, std::string* error) {
    if (error) error->clear();
    if (!stopShape(stop) || !instanceScope(slot.scope) || !slot.instanceId || slot.frameId ||
        slot.storage != GmlSlotStorage::Canonical || slot.availability != GmlValueAvailability::Available ||
        slot.writable != 1 || numericKind(slot.value.typeTag) != slot.kind || slot.kind == GmlNumericKind::None)
        return fail(error, "The selected slot is not a captured canonical instance numeric value");
    bool captured = false;
    for (uint32_t i = 0; i < stop.numericSlotCount; ++i) {
        const auto& old = stop.numericSlots[i];
        captured = captured || (old.scope == slot.scope && old.address == slot.address &&
            old.ownerObject == slot.ownerObject && old.instanceId == slot.instanceId &&
            old.runtimeInstanceNumber == slot.runtimeInstanceNumber && old.objectIndex == slot.objectIndex &&
            old.runtimeVariableId == slot.runtimeVariableId && old.value == slot.value);
    }
    if (!captured) return fail(error, "The numeric slot does not belong to this stop snapshot");
    try {
        FrozenRegistry frozen;
        if (!loadFrozen(reader, base, lifetimesAddress, capacity, frozen, error)) return false;
        if (!matches(frozen, slot.ownerObject, slot.instanceId, slot.runtimeInstanceNumber, slot.objectIndex))
            return fail(error, "The numeric owner was removed or its allocation identity changed");
        const auto& object = frozen.instance(slot.ownerObject)->object;
        GmlRunnerVariableMapView map;
        if (!object.variableMap || !ReadGmlRunnerVariableMap(reader, object.variableMap, map))
            return fail(error, "The numeric owner's canonical variable map is unavailable");
        uint32_t found = 0, matchesId = 0;
        for (uint32_t i = 0; i < map.capacity; ++i) {
            GmlRunnerVariableEntry entry;
            if (!ReadGmlRunnerVariableEntry(reader, map, i, entry))
                return fail(error, "The canonical variable map has an invalid entry");
            if (!entry.valueAddress) continue;
            ++found;
            if (entry.runtimeId == slot.runtimeVariableId) {
                ++matchesId;
                if (entry.valueAddress != slot.address)
                    return fail(error, "The canonical numeric value address changed");
            }
        }
        if (matchesId != 1 || found != map.count || !mapUnchanged(reader, base, object, map))
            return fail(error, "The numeric slot has no unique stable canonical map owner");
        return sameLifetimes(reader, lifetimesAddress, frozen, error);
    } catch (const std::bad_alloc&) {
        return fail(error, "Insufficient host memory for bounded instance ownership validation");
    }
}
} // namespace ds
