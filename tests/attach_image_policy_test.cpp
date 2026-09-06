#include "Core/AttachImagePolicy.h"

#include <cstdio>

using namespace ds;

static int g_fail = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL line %d: %s\n", __LINE__, #x); ++g_fail; } } while (0)

int main() {
    CHECK(SameAttachSession({1234, 7}, {1234, 7}));
    CHECK(!SameAttachSession({1234, 7}, {1234, 8})); // PID reuse / reattach
    CHECK(!SameAttachSession({1234, 7}, {4321, 7}));
    CHECK(!SameAttachSession({}, {1234, 7}));

    CHECK(AttachedImagePathsMatch(
        "C:\\Lab\\CrackMe.exe", "\\\\?\\c:\\lab\\.\\CRACKME.EXE"));
    CHECK(AttachedImagePathsMatch(
        "\\\\Server\\Share\\Apps\\CrackMe.exe",
        "\\\\?\\UNC\\server\\share\\apps\\sub\\..\\crackme.exe"));
    CHECK(!AttachedImagePathsMatch("CrackMe.exe", "C:\\Lab\\CrackMe.exe"));
    CHECK(!AttachedImagePathsMatch("C:\\One\\CrackMe.exe",
                                   "D:\\Two\\CrackMe.exe"));
    CHECK(NormalizeAttachedImagePath("C:\\..\\CrackMe.exe").empty());

    AttachMainImageState state;
    CHECK(DecideAttachMainImage(state) ==
          AttachMainImageAction::OpenEphemeralMainImage); // empty scratch

    state.activeLoaded = true;
    state.activePe = true;
    state.activeArchitectureMatchesSession = true;
    state.activeFullPathMatchesMain = true;
    state.activeBackingFileMatchesMain = true;
    CHECK(DecideAttachMainImage(state) ==
          AttachMainImageAction::KeepMatchingFileDocument);

    state.activeBackingFileMatchesMain = false;
    CHECK(DecideAttachMainImage(state) ==
          AttachMainImageAction::OpenEphemeralMainImage); // same path, patches/unproven bytes/file
    state.activeBackingFileMatchesMain = true;

    state.activeMapped = true;
    CHECK(DecideAttachMainImage(state) ==
          AttachMainImageAction::OpenEphemeralMainImage); // stale/unproven live capture

    state.activeMapped = false;
    state.activeFullPathMatchesMain = false;
    CHECK(DecideAttachMainImage(state) ==
          AttachMainImageAction::OpenEphemeralMainImage); // unrelated file

    state.activeFullPathMatchesMain = true;
    state.activeArchitectureMatchesSession = false;
    CHECK(DecideAttachMainImage(state) ==
          AttachMainImageAction::OpenEphemeralMainImage); // replaced/inconsistent file

    state.hostedDllLaunch = true;
    CHECK(DecideAttachMainImage(state) ==
          AttachMainImageAction::DeferToHostedDllTarget);

    AttachedFileIdentity disk{true, 7, 0x11223344, 12345, 67890};
    CHECK(SameAttachedFileIdentity(disk, disk));
    AttachedFileIdentity replaced = disk;
    ++replaced.fileIndex;
    CHECK(!SameAttachedFileIdentity(disk, replaced));
    replaced = disk;
    ++replaced.lastWriteTime;
    CHECK(!SameAttachedFileIdentity(disk, replaced));
    replaced = disk;
    replaced.valid = false;
    CHECK(!SameAttachedFileIdentity(disk, replaced));

    const AttachedModuleIdentity module{
        0x140000000ull, 0x9000, "CrackMe.exe", "C:\\Lab\\CrackMe.exe", 7
    };
    CHECK(AttachedModuleIdentityMatches(
        module,
        {0x140000000ull, 0x9000, "crackme.exe", "\\\\?\\c:\\lab\\CRACKME.EXE", 7}));
    CHECK(!AttachedModuleIdentityMatches(
        module,
        {0x140000000ull, 0x9000, "crackme.exe", "C:\\Lab\\CrackMe.exe", 8}));
    CHECK(!AttachedModuleIdentityMatches(
        module,
        {0x150000000ull, 0x9000, "CrackMe.exe", "C:\\Lab\\CrackMe.exe", 7}));
    CHECK(!AttachedModuleIdentityMatches(
        module,
        {0x140000000ull, 0xA000, "CrackMe.exe", "C:\\Lab\\CrackMe.exe", 7}));
    CHECK(!AttachedModuleIdentityMatches(
        module,
        {0x140000000ull, 0x9000, "CrackMe.exe", "D:\\Other\\CrackMe.exe", 7}));
    CHECK(AttachedModuleIdentityMatches(
        {0x400000, 0, "<main@0x400000>", {}},
        {0x400000, 0x8000, "<MAIN@0x400000>", {}}));
    CHECK(!AttachedModuleIdentityMatches(
        {0x400000, 0, "<main@0x400000>", {}},
        {0x400000, 0x8000, "<main@0x400000>", "C:\\Known.exe"}));

    if (g_fail) {
        std::printf("attach_image_policy_test: %d failure(s)\n", g_fail);
        return 1;
    }
    std::printf("attach_image_policy_test: all checks passed\n");
    return 0;
}
