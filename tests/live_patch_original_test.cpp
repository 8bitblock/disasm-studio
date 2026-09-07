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

    // A overlaps B, and B overlaps C outside A. Removing A may restore only
    // A's span: replaying B in full would corrupt C's already-applied byte.
    {
        const PjPatch a{ 0x1000, { 0xF0, 0xF1 }, { 0xA0, 0xA1 } };
        const PjPatch b{ 0x1001, { 0xF1, 0xF2, 0xF3 }, { 0xB1, 0xB2, 0xB3 } };
        const PjPatch c{ 0x1003, { 0xF3, 0xF4 }, { 0xC3, 0xC4 } };
        LivePatchOriginalMap originals{
            { a.address, { owner, 0x5000, { 0x10, 0x11 } } },
            { b.address, { owner, 0x5001, { 0x11, 0x12, 0x13 } } },
            { c.address, { owner, 0x5003, { 0x13, 0x14 } } },
        };
        const std::unordered_map<uint64_t, uint64_t> owners{
            { a.address, 0 }, { b.address, 0 }, { c.address, 0 },
        };
        auto restored = PlanLivePatchRestoration(originals, owners, owner, a, { b, c });
        CHECK(restored.success && restored.runtimeVA == 0x5000);
        CHECK(restored.bytes == (std::vector<uint8_t>{ 0x10, 0xB1 }));
        std::vector<uint8_t> live{ 0xA0, 0xB1, 0xB2, 0xC3, 0xC4 };
        if (restored.success && restored.bytes.size() <= live.size())
            std::copy(restored.bytes.begin(), restored.bytes.end(), live.begin());
        CHECK(live == (std::vector<uint8_t>{ 0x10, 0xB1, 0xB2, 0xC3, 0xC4 }));

        originals[b.address].runtimeVA = 0x6001;
        restored = PlanLivePatchRestoration(originals, owners, owner, a, { b, c });
        CHECK(!restored.success && restored.bytes.empty() &&
              restored.error == LivePatchOriginalError::RuntimeMappingConflict);
        originals[b.address].runtimeVA = 0x5001;
        originals[b.address].bytes.pop_back();
        restored = PlanLivePatchRestoration(originals, owners, owner, a, { b, c });
        CHECK(!restored.success && restored.bytes.empty() &&
              restored.error == LivePatchOriginalError::SpanMismatch);
    }

    // Only the set that actually wrote a retained live span may contribute.
    // Static-only records, including another set at the same FILE address,
    // cannot be introduced into the process by reverting a different patch.
    {
        const PjPatch removed{ 0x1000, { 0xF0, 0xF1, 0xF2 }, { 0xA0, 0xA1, 0xA2 } };
        const PjPatch livePatch{ 0x1001, { 0xF1 }, { 0xB1 }, 2 };
        const PjPatch staticAlternative{ 0x1001, { 0xF1 }, { 0xE1 }, 3 };
        const PjPatch staticOnly{ 0x1002, { 0xF2 }, { 0xE2 } };
        LivePatchOriginalMap originals{
            { removed.address, { owner, 0x5000, { 0x10, 0x11, 0x12 } } },
            { livePatch.address, { owner, 0x5001, { 0x11 } } },
        };
        std::unordered_map<uint64_t, uint64_t> owners{
            { removed.address, 0 }, { livePatch.address, 2 },
        };
        ProjectState project;
        project.patchSets = { { 2, "Previously live", false }, { 3, "Static alternative", true } };
        project.patches = { livePatch, staticAlternative, staticOnly };
        auto restored = PlanLivePatchRestoration(originals, owners, owner,
                                                 removed, project.patches);
        CHECK(restored.success);
        // Disabling set 2 changed FILE only, so its live byte still survives.
        // Both unshadowed originals are runtime values, never persisted 0xF*.
        CHECK(restored.bytes == (std::vector<uint8_t>{ 0x10, 0xB1, 0x12 }));

        originals[livePatch.address].owner.sessionGeneration++;
        restored = PlanLivePatchRestoration(originals, owners, owner,
                                            removed, project.patches);
        CHECK(restored.success &&
              restored.bytes == (std::vector<uint8_t>{ 0x10, 0x11, 0x12 }));
        owners[removed.address] = 9;
        restored = PlanLivePatchRestoration(originals, owners, owner, removed, {});
        CHECK(!restored.success && restored.bytes.empty() &&
              restored.error == LivePatchOriginalError::PatchSetOwnerConflict);
    }

    // Survivors compose in recorded order, with both left-edge clipping and
    // later overwrites inside the removed span.
    {
        const PjPatch removed{ 0x1001, { 1, 2, 3 }, { 0xA1, 0xA2, 0xA3 } };
        const PjPatch left{ 0x1000, { 0, 1, 2 }, { 0xB0, 0xB1, 0xB2 } };
        const PjPatch later{ 0x1002, { 2, 3, 4 }, { 0xC2, 0xC3, 0xC4 } };
        LivePatchOriginalMap originals{
            { removed.address, { owner, 0x5001, { 0x11, 0x12, 0x13 } } },
            { left.address, { owner, 0x5000, { 0x10, 0x11, 0x12 } } },
            { later.address, { owner, 0x5002, { 0x12, 0x13, 0x14 } } },
        };
        const std::unordered_map<uint64_t, uint64_t> owners{
            { removed.address, 0 }, { left.address, 0 }, { later.address, 0 },
        };
        auto restored = PlanLivePatchRestoration(originals, owners, owner, removed, { left, later });
        CHECK(restored.success && restored.runtimeVA == 0x5001);
        CHECK(restored.bytes == (std::vector<uint8_t>{ 0xB1, 0xC2, 0xC3 }));
        restored = PlanLivePatchRestoration(originals, owners, owner, removed, { later, left });
        CHECK(restored.success && restored.bytes == (std::vector<uint8_t>{ 0xB1, 0xB2, 0xC3 }));

        originals[removed.address].runtimeVA = std::numeric_limits<uint64_t>::max() - 1;
        restored = PlanLivePatchRestoration(originals, owners, owner, removed, {});
        CHECK(!restored.success && restored.bytes.empty() &&
              restored.error == LivePatchOriginalError::AddressOverflow);
        originals[removed.address].runtimeVA = 0x5001;
        originals[removed.address].bytes.pop_back();
        restored = PlanLivePatchRestoration(originals, owners, owner, removed, {});
        CHECK(!restored.success && restored.bytes.empty() &&
              restored.error == LivePatchOriginalError::SpanMismatch);
        originals.erase(removed.address);
        restored = PlanLivePatchRestoration(originals, owners, owner, removed, {});
        CHECK(!restored.success && restored.bytes.empty() &&
              restored.error == LivePatchOriginalError::OriginalUnavailable);
    }

    if (g_fail == 0) std::printf("ALL LIVE PATCH ORIGINAL TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
