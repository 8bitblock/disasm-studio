// Pure regression coverage for session-scoped live patch rollback planning.
#include "Core/LivePatchOriginal.h"
#include "Core/Project.h"

#include <cstdint>
#include <cstdio>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    const DebugTargetIdentity owner{ 1234, 7 };
    LivePatchOriginalMap retained;
    size_t retainedBytes = 0;

    // First capture retains the identity-checked bytes as-is.
    auto first = PlanLivePatchOriginal(
        retained, retainedBytes, owner, 0x1000, 0x5000, { 0x11, 0x22, 0x33 });
    CHECK(first.success);
    CHECK(first.original.bytes == (std::vector<uint8_t>{ 0x11, 0x22, 0x33 }));
    retainedBytes = first.retainedBytesAfter;
    retained[0x1000] = std::move(first.original);

    // An overlapping capture observes the first patch in the process, then
    // reconstructs the true runtime original from the retained record.
    auto overlap = PlanLivePatchOriginal(
        retained, retainedBytes, owner, 0x1001, 0x5001, { 0xA1, 0xA2, 0x44 });
    CHECK(overlap.success);
    CHECK(overlap.original.bytes == (std::vector<uint8_t>{ 0x22, 0x33, 0x44 }));

    // A same-address repatch reuses the first original rather than capturing
    // the already-patched bytes as its future rollback value.
    auto repatch = PlanLivePatchOriginal(
        retained, retainedBytes, owner, 0x1000, 0x5000, { 0xA0, 0xA1, 0xA2 });
    CHECK(repatch.success);
    CHECK(repatch.original.bytes == (std::vector<uint8_t>{ 0x11, 0x22, 0x33 }));
    CHECK(repatch.retainedBytesAfter == retainedBytes);

    // PID alone is insufficient, and a changed runtime mapping in one retained
    // session must fail closed.
    auto wrongGeneration = PlanLivePatchOriginal(
        retained, retainedBytes, { owner.pid, owner.sessionGeneration + 1 },
        0x1000, 0x5000, { 1, 2, 3 });
    CHECK(!wrongGeneration.success);
    CHECK(wrongGeneration.error == LivePatchOriginalError::OwnerConflict);
    auto moved = PlanLivePatchOriginal(
        retained, retainedBytes, owner, 0x1001, 0x6001, { 1, 2, 3 });
    CHECK(!moved.success);
    CHECK(moved.error == LivePatchOriginalError::RuntimeMappingConflict);

    CHECK(FindLivePatchOriginal(retained, 0x1000, owner, 0x5000, 3) != nullptr);
    CHECK(FindLivePatchOriginal(retained, 0x1000,
          { owner.pid, owner.sessionGeneration + 1 }, 0x5000, 3) == nullptr);
    CHECK(FindLivePatchOriginal(retained, 0x1000, owner, 0x6000, 3) == nullptr);
    CHECK(FindLivePatchOriginal(retained, 0x1000, owner, 0x5000, 2) == nullptr);

    // Same-address persisted repatches may not change span length or inherit a
    // corrupt mismatched orig; both cases would leave bytes outside the record.
    const PjPatch valid{ 0x1000, { 1, 2, 3 }, { 4, 5, 6 } };
    const PjPatch corrupt{ 0x1000, { 1, 2 }, { 4, 5, 6 } };
    CHECK(PatchRecordCanBeReplacedInPlace(valid, 3));
    CHECK(!PatchRecordCanBeReplacedInPlace(valid, 2));
    CHECK(!PatchRecordCanBeReplacedInPlace(valid, 4));
    CHECK(!PatchRecordCanBeReplacedInPlace(corrupt, 3));

    if (g_fail == 0) std::printf("ALL LIVE PATCH ORIGINAL TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
