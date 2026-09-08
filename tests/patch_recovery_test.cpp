#include "Core/PatchRecovery.h"
#include "Core/Project.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;
static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)

int main() {
    const std::string path = "patch_recovery_fixture.raw";
    const std::vector<uint8_t> original{0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    { std::ofstream file(path, std::ios::binary); file.write(reinterpret_cast<const char*>(original.data()), original.size()); }
    BinaryFile image;
    CHECK(image.loadRaw(path, 0));
    ProjectState project;
    project.patchSets = {{7, "disabled", false}};
    project.patches = {{0, {0x10, 0x20}, {0x90, 0x90}},
                       {1, {0x20, 0x30}, {0xCC, 0xCC}},
                       {5, {0x99}, {0x70}, 7}};
    size_t commits = 0;
    auto commit = [&](std::vector<uint8_t> bytes) { ++commits; return image.commitPatchedImage(std::move(bytes)); };

    // A bad disabled record still invalidates the whole saved selection. A
    // valid prefix cannot be committed, marked active, or silently removed.
    auto result = RecoverSavedPatchSelection(image, project, commit);
    CHECK(!result.success && result.error == PatchRecoveryError::InvalidSelection);
    CHECK(result.selection.failedPatch == 2);
    CHECK(project.patchRecoveryPending && project.patches.size() == 3);
    CHECK(project.patchSets.size() == 1 && !project.patchSets[0].enabled);
    CHECK(commits == 0 && image.bytes() == original);
    CHECK(!ForgetUnrestoredPatch(image, project, 3));
    CHECK(project.patches.size() == 3);

    // Repeated failure retains exact order/data. Session state is not written
    // into JSON, so reopening independently validates the saved intent again.
    result = RecoverSavedPatchSelection(image, project, commit);
    CHECK(!result.success && project.patches[2].orig == std::vector<uint8_t>{0x99});
    const std::string json = SerializeProject(project);
    ProjectState reopened;
    CHECK(DeserializeProject(json, reopened));
    CHECK(reopened.patches.size() == 3 && !reopened.patchRecoveryPending);
    CHECK(reopened.patches[0].address == 0 && reopened.patches[1].address == 1);

    // Removing exactly the rejected record allows ordered legacy overlaps.
    CHECK(ForgetUnrestoredPatch(image, project, 2));
    CHECK(project.patchRecoveryPending && project.patches.size() == 2);
    result = RecoverSavedPatchSelection(image, project, commit);
    CHECK(result.success && result.imageChanged && commits == 1);
    CHECK(!project.patchRecoveryPending && project.patchRecoveryImageRevision == 0);
    CHECK(image.bytes() == std::vector<uint8_t>({0x90, 0xCC, 0xCC, 0x40, 0x50, 0x60}));
    CHECK(!ForgetUnrestoredPatch(image, project, 0));

    // A failed commit keeps the complete list retryable on the same pristine
    // image. This covers failures after successful validation/allocation.
    CHECK(image.loadRaw(path, 0));
    result = RecoverSavedPatchSelection(image, project, [](std::vector<uint8_t>) { return false; });
    CHECK(!result.success && result.error == PatchRecoveryError::CommitFailed);
    CHECK(project.patchRecoveryPending && project.patches.size() == 2 && image.bytes() == original);
    result = RecoverSavedPatchSelection(image, project, commit);
    CHECK(result.success && commits == 2);

    // External byte changes after a rejected commit retire recovery authority.
    CHECK(image.loadRaw(path, 0));
    result = RecoverSavedPatchSelection(image, project, [](std::vector<uint8_t>) { return false; });
    const uint8_t unrelated = 0x61;
    CHECK(image.writeImage(5, &unrelated, 1) == 1);
    result = RecoverSavedPatchSelection(image, project, commit);
    CHECK(!result.success && result.error == PatchRecoveryError::ImageChanged && commits == 2);
    CHECK(!ForgetUnrestoredPatch(image, project, 0));
    CHECK(project.patches.size() == 2 && project.patchRecoveryPending);

    std::remove(path.c_str());
    std::printf("patch_recovery_test: %s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
