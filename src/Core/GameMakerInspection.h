#pragma once

#include "GameMakerDebugProtocol.h"
#include "GameMakerRunner.h"
#include <string>

namespace ds {

// Host-side read-only projection. The caller must own the authenticated held
// Win32 event for stop.identity throughout this call. The helper's committed
// lifetime table and the exact runner profile must belong to that session.
// UINT32_MAX/0 selects no variable domain; the registry is still refreshed.
// A non-default object selector and nonzero instance selector are exclusive.
// Previously inspected instance domains are reprojected under this same event,
// with the newly selected domain given space first. Slot indices may change;
// queued edits/UI selection must retain full slot identity or reject revisions.
// On success stop is replaced transactionally; incomplete bounded coverage is
// explicit in its completeness/availability fields. On failure stop is unchanged.
bool InspectGmlFrozenInstances(const GmlRunnerReader&, uint64_t runnerBase,
    uint64_t lifetimesAddress, uint32_t lifetimesCapacity,
    uint32_t selectedObjectIndex, uint64_t selectedInstanceId,
    GmlHelperStop& stop, std::string* error = nullptr);

// Proves one existing instance-scoped slot still belongs to the exact current
// allocation token, registry object/raw ID, and canonical variable map entry.
// This does not write or authorize another debug event. Numeric-edit code must
// separately compare the full fresh RValue and retain the held-event authority.
bool ValidateGmlFrozenInstanceSlotOwnership(const GmlRunnerReader&, uint64_t runnerBase,
    uint64_t lifetimesAddress, uint32_t lifetimesCapacity,
    const GmlHelperStop& stop, const GmlHelperNumericSlot& slot,
    std::string* error = nullptr);

} // namespace ds
