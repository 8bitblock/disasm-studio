// Local live-validation harness only; compiled into tools/gamemaker/.cache.
#include "../../src/Core/GameMakerRunner.h"
extern "C" __declspec(dllexport) unsigned VerifySnapshot(ds::GmlRunnerRead read, void* owner,
    uint64_t base, uint64_t context, unsigned pc, uint64_t stack) {
    ds::GmlRunnerReader reader{owner, read};
    ds::GmlRunnerContextView frame;
    unsigned result = 0;
    if (!ds::ReadGmlRunnerContext(reader, base, context, pc, stack, frame)) return result;
    result |= 1;
    uint64_t anchor = frame.anchor;
    bool complete = true;
    for (unsigned i = 0; i < frame.logicalDepth; ++i) {
        ds::GmlRunnerSavedFrameView saved;
        if (!ds::ReadGmlRunnerSavedFrame(reader, base, frame, anchor, saved)) { complete = false; break; }
        anchor = saved.previousAnchor;
    }
    if (complete) result |= 2;
    uint64_t global = 0;
    reader.copy(base + ds::NubbyGameMakerRunner().globalObjectRva, &global, sizeof(global));
    uint64_t objects[] = {frame.localObject, frame.self, global};
    for (unsigned i = 0; i < 3; ++i) {
        if (!objects[i]) continue;
        ds::GmlRunnerObjectView object;
        if (!ds::ReadGmlRunnerObject(reader, base, objects[i], object)) continue;
        result |= 1u << (2 + i);
        if (!object.variableMap) continue;
        ds::GmlRunnerVariableMapView map;
        if (!ds::ReadGmlRunnerVariableMap(reader, object.variableMap, map)) continue;
        unsigned observed = 0;
        bool valid = true;
        for (unsigned n = 0; n < map.capacity; ++n) {
            ds::GmlRunnerVariableEntry entry;
            if (!ds::ReadGmlRunnerVariableEntry(reader, map, n, entry)) { valid = false; break; }
            if (entry.valueAddress) {
                ++observed;
                char name[1024];
                if (!ds::ReadGmlRunnerVariableName(reader, base, entry.runtimeId, name, sizeof(name))) { valid = false; break; }
            }
        }
        if (valid && observed == map.count) result |= 1u << (5 + i);
    }
    return result;
}
