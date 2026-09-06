// Pure/model plus BinaryFile-backed regression coverage for named patch-set
// experiments. Conflicting enabled alternatives fail closed, selection order is
// stable, and every transition is recomposed from recorded pristine bytes.

#include "Core/PatchSet.h"
#include "Core/PatchedImage.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)

int main() {
    std::vector<PjPatchSet> sets{
        { 1, "Global gate only", true },
        { 2, "Global + feature gates", false },
    };
    std::vector<PjPatch> patches{
        { 0x1001, { 0x11 }, { 0xA1 }, 1 },
        { 0x1003, { 0x13 }, { 0xB3 }, 2 },
    };

    PjPatchSetPlan plan = BuildPatchSetPlan(patches, sets);
    CHECK(plan.success && plan.activePatchIndices.size() == 1 &&
          plan.activePatchIndices[0] == 0);
    plan = BuildPatchSetPlan(patches, sets,
        { { 1, false }, { 2, true } });
    CHECK(plan.success && plan.activePatchIndices.size() == 1 &&
          plan.activePatchIndices[0] == 1);
    plan = BuildPatchSetPlan(patches, sets,
        { { 0, false }, { 1, false }, { 2, false } });
    CHECK(plan.success && plan.activePatchIndices.empty());

    // Worker snapshots contain only the validated active selection, retain
    // global application order, and clear stale output when selection fails.
    std::vector<PjPatch> snapshot{
        { 0xDEAD, { 0x00 }, { 0xFF }, 0 },
    };
    plan = SnapshotActivePatchRecords(patches, sets, snapshot);
    CHECK(plan.success && snapshot.size() == 1 &&
          snapshot[0].address == 0x1001 && snapshot[0].patchSetId == 1);
    plan = SnapshotActivePatchRecords(
        patches, sets, snapshot, { { 1, false }, { 2, true } });
    CHECK(plan.success && snapshot.size() == 1 &&
          snapshot[0].address == 0x1003 && snapshot[0].patchSetId == 2);
    plan = SnapshotActivePatchRecords(
        patches, sets, snapshot, { { 2, true } });
    CHECK(plan.success && snapshot.size() == 2 &&
          snapshot[0].address == 0x1001 && snapshot[1].address == 0x1003);
    plan = SnapshotActivePatchRecords(
        patches, sets, snapshot,
        { { 0, false }, { 1, false }, { 2, false } });
    CHECK(plan.success && snapshot.empty());

    // A user can keep mutually-exclusive alternatives in one project, but an
    // attempted state that enables both conflicting writes is an explicit
    // error with both record indices and the first ambiguous address.
    std::vector<PjPatch> alternatives{
        { 0x2000, { 0x31, 0xC0 }, { 0xB0, 0x01 }, 1 },
        { 0x2000, { 0x31, 0xC0 }, { 0x30, 0xC0 }, 2 },
    };
    plan = BuildPatchSetPlan(alternatives, sets, { { 2, true } });
    CHECK(!plan.success &&
          plan.error == PjPatchSetPlanError::ActiveOverlapConflict &&
          plan.failedPatch == 0 && plan.conflictingPatch == 1 &&
          plan.conflictAddress == 0x2000);
    plan = SnapshotActivePatchRecords(
        alternatives, sets, snapshot, { { 2, true } });
    CHECK(!plan.success &&
          plan.error == PjPatchSetPlanError::ActiveOverlapConflict &&
          snapshot.empty());
    plan = BuildPatchSetPlan(alternatives, sets,
        { { 1, false }, { 2, true } });
    CHECK(plan.success && plan.activePatchIndices.size() == 1 &&
          plan.activePatchIndices[0] == 1);

    // Pre-v4 Ungrouped records retain their documented ordered later-wins
    // behavior. The exception is deliberately confined to id zero.
    std::vector<PjPatch> legacy{
        { 0x3000, { 0x01, 0x02 }, { 0xA1, 0xA2 }, 0 },
        { 0x3001, { 0x02, 0x03 }, { 0xB2, 0xB3 }, 0 },
    };
    plan = BuildPatchSetPlan(legacy, {});
    CHECK(plan.success && plan.activePatchIndices.size() == 2 &&
          plan.activePatchIndices[0] == 0 &&
          plan.activePatchIndices[1] == 1);

    std::vector<PjPatch> badOriginals = alternatives;
    badOriginals[1].orig[0] = 0xFF;
    plan = BuildPatchSetPlan(badOriginals, sets,
        { { 1, false }, { 2, false } });
    CHECK(!plan.success &&
          plan.error == PjPatchSetPlanError::OriginalOverlapMismatch);

    CHECK(!BuildPatchSetPlan({}, { { 0, "reserved", true } }).success);
    CHECK(BuildPatchSetPlan({}, { { 1, "Gate", true },
                                  { 2, "gate", false } }).error ==
          PjPatchSetPlanError::DuplicateSetName);
    CHECK(BuildPatchSetPlan({}, sets, { { 99, true } }).error ==
          PjPatchSetPlanError::UnknownPatchSet);
    CHECK(BuildPatchSetPlan({}, sets, { { 1, true }, { 1, false } }).error ==
          PjPatchSetPlanError::DuplicateSelectionOverride);
    uint64_t nextId = 0;
    CHECK(NextPatchSetId(sets, nextId) && nextId == 3);

    const std::string path = "patch_set_fixture.bin";
    const std::vector<uint8_t> pristine{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char*>(pristine.data()),
                   static_cast<std::streamsize>(pristine.size()));
    }
    BinaryFile binary;
    CHECK(binary.loadRaw(path, 0x1000));

    // Start from the on-disk pristine image and materialize the project's
    // currently enabled Global-only selection.
    PatchSetImageResult global = BuildPatchSetImageForSelection(
        binary, patches, sets, {}, PatchSetImageSource::Pristine);
    CHECK(global.success && global.image.size() == pristine.size());
    CHECK(global.image[1] == 0xA1 && global.image[3] == 0x13);
    CHECK(global.changedByteCount == 1 && global.changes.size() == 1 &&
          global.changes[0].fileOffset == 1 &&
          global.changes[0].addressValid &&
          global.changes[0].address == 0x1001);
    CHECK(binary.writeImage(0x1001, &global.image[1], 1) == 1);

    // Enable the feature set from a verified Global-only source. The result is
    // recomposed from pristine bytes and changes only the feature byte.
    PatchSetImageResult both = BuildPatchSetImageForSelection(
        binary, patches, sets, { { 2, true } });
    CHECK(both.success && both.image[1] == 0xA1 && both.image[3] == 0xB3);
    CHECK(both.changedByteCount == 1 && both.changes.size() == 1 &&
          both.changes[0].fileOffset == 3);

    PatchSetComparisonResult comparison = ComparePatchSetSelections(
        binary, patches, sets, {}, { { 2, true } });
    CHECK(comparison.success && comparison.differentByteCount == 1 &&
          comparison.differences.size() == 1 &&
          comparison.differences[0].fileOffset == 3 &&
          comparison.differences[0].before[0] == 0x13 &&
          comparison.differences[0].after[0] == 0xB3);

    std::vector<PjPatch> byteAlternatives{
        { 0x1001, { 0x11 }, { 0xA1 }, 1 },
        { 0x1001, { 0x11 }, { 0xC1 }, 2 },
    };
    PatchSetImageResult switched = BuildPatchSetImageForSelection(
        binary, byteAlternatives, sets, { { 1, false }, { 2, true } });
    CHECK(switched.success && switched.image[1] == 0xC1 &&
          switched.changes.size() == 1 &&
          switched.changes[0].before[0] == 0xA1 &&
          switched.changes[0].after[0] == 0xC1);

    // Baseline disables every set, including implicit Ungrouped, and restores
    // exact pristine bytes rather than capturing the Global experiment as its
    // new original state.
    PatchSetImageResult baseline = BuildPatchSetImageForSelection(
        binary, patches, sets,
        { { 0, false }, { 1, false }, { 2, false } });
    CHECK(baseline.success && baseline.image == pristine &&
          baseline.changedByteCount == 1);

    // If the live image no longer contains the advertised current selection,
    // recomposition fails without publishing a partial candidate.
    const uint8_t tampered = 0xFE;
    CHECK(binary.writeImage(0x1001, &tampered, 1) == 1);
    PatchSetImageResult stale = BuildPatchSetImageForSelection(
        binary, patches, sets, { { 2, true } });
    CHECK(!stale.success && stale.image.empty() &&
          stale.error == PatchSetImageError::CurrentStateMismatch);

    std::remove(path.c_str());
    if (failures) {
        std::fprintf(stderr, "%d patch-set check(s) failed\n", failures);
        return 1;
    }
    std::puts("patch set tests passed");
    return 0;
}
