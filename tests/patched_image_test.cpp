// Transactional Save Binary As patch-list construction. This is deliberately
// ImGui-free: invalid persisted state must fail before any output file is
// opened, and a bad later record must not leave an image containing the valid
// prefix of the list.

#include "Core/PatchedImage.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); ++failures; } } while (0)

static void Put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

static void Put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

// Two distinct VAs deliberately map the same raw file range. Patch ordering is
// defined by the resulting file image, so span planning must recognize this as
// overlap even though the virtual ranges are disjoint.
static std::vector<uint8_t> BuildAliasedPE32() {
    std::vector<uint8_t> bytes(0x600, 0);
    bytes[0] = 'M';
    bytes[1] = 'Z';
    constexpr uint32_t peOffset = 0x80;
    Put32(bytes, 0x3C, peOffset);
    Put32(bytes, peOffset, 0x00004550);

    constexpr size_t coff = peOffset + 4;
    Put16(bytes, coff + 0, 0x014C);
    Put16(bytes, coff + 2, 2);
    Put16(bytes, coff + 16, 0xE0);
    Put16(bytes, coff + 18, 0x102);

    constexpr size_t optional = coff + 20;
    Put16(bytes, optional + 0, 0x10B);
    Put32(bytes, optional + 16, 0x1000);
    Put32(bytes, optional + 28, 0x400000);
    Put32(bytes, optional + 32, 0x1000);
    Put32(bytes, optional + 36, 0x200);
    Put32(bytes, optional + 56, 0x3000);
    Put32(bytes, optional + 60, 0x400);
    Put32(bytes, optional + 92, 16);

    constexpr size_t firstSection = optional + 0xE0;
    constexpr size_t secondSection = firstSection + 40;
    std::memcpy(bytes.data() + firstSection, ".one", 4);
    std::memcpy(bytes.data() + secondSection, ".two", 4);
    for (const auto section : { firstSection, secondSection }) {
        Put32(bytes, section + 8, 0x200);
        Put32(bytes, section + 16, 0x200);
        Put32(bytes, section + 20, 0x400);
        Put32(bytes, section + 36, 0x60000020u);
    }
    Put32(bytes, firstSection + 12, 0x1000);
    Put32(bytes, secondSection + 12, 0x2000);
    bytes[0x410] = 0x31;
    bytes[0x411] = 0x32;
    return bytes;
}

static PatchRemovalSpanResult CheckSpanMatchesFullImage(
    const BinaryFile& binary,
    const std::vector<PjPatch>& patches,
    size_t removeIndex) {
    const PatchedImageResult full =
        BuildImageAfterPatchRemoval(binary, patches, removeIndex);
    PatchRemovalSpanResult span =
        BuildPatchRemovalSpan(binary, patches, removeIndex);
    CHECK(span.success == full.success);
    CHECK(span.error == full.error);
    CHECK(span.appliedPatches == full.appliedPatches);
    CHECK(span.failedPatch == full.failedPatch);
    CHECK(span.failedAddress == full.failedAddress);
    if (span.success && full.success) {
        std::vector<uint8_t> rebuilt = binary.bytes();
        if (!span.bytes.empty()) {
            uint64_t fileOffset = 0;
            CHECK(binary.vaToOffset(span.address, fileOffset));
            CHECK(fileOffset <= rebuilt.size());
            if (fileOffset <= rebuilt.size()) {
                CHECK(span.bytes.size() <=
                      rebuilt.size() - static_cast<size_t>(fileOffset));
                if (span.bytes.size() <=
                    rebuilt.size() - static_cast<size_t>(fileOffset)) {
                    std::copy(span.bytes.begin(), span.bytes.end(),
                              rebuilt.begin() + static_cast<size_t>(fileOffset));
                }
            }
        }
        CHECK(rebuilt == full.image);
    } else {
        CHECK(span.bytes.empty());
    }
    return span;
}

int main() {
    const std::string path = "patched_image_fixture.bin";
    const std::vector<uint8_t> pristine{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    };
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char*>(pristine.data()),
                   static_cast<std::streamsize>(pristine.size()));
    }

    BinaryFile binary;
    CHECK(binary.loadRaw(path, 0));

    // A fully valid list is applied in persisted order. Later overlapping
    // patches win, including when VA zero is the first mapped address.
    std::vector<PjPatch> valid{
        { 0, { 0x10, 0x11, 0x12 }, { 0xA0, 0xA1, 0xA2 } },
        { 2, { 0x12, 0x13 },       { 0xB2, 0xB3 } },
    };
    PatchedImageResult made = BuildPatchedImage(
        binary, valid, PatchedImageSource::Pristine);
    CHECK(made.success);
    CHECK(made.error == PatchedImageError::None);
    CHECK(made.appliedPatches == 2);
    CHECK(made.image.size() == pristine.size());
    if (made.image.size() == pristine.size()) {
        CHECK(made.image[0] == 0xA0 && made.image[1] == 0xA1);
        CHECK(made.image[2] == 0xB2 && made.image[3] == 0xB3);
        CHECK(made.image[4] == pristine[4]);
    }
    CHECK(binary.bytes() == pristine); // building never mutates the source image

    // A valid first record followed by a range crossing the file end fails the
    // whole list. No partially patched output is returned.
    std::vector<PjPatch> lateUnmapped{
        valid.front(),
        { 7, { 0x17, 0x00 }, { 0xC7, 0xC8 } },
    };
    made = BuildPatchedImage(binary, lateUnmapped, PatchedImageSource::Pristine);
    CHECK(!made.success);
    CHECK(made.error == PatchedImageError::RangeNotFileBacked);
    CHECK(made.failedPatch == 1 && made.failedAddress == 7);
    CHECK(made.appliedPatches == 0 && made.image.empty());
    CHECK(binary.bytes() == pristine);

    std::vector<PjPatch> malformed{
        { 1, { 0x11 }, { 0xD1, 0xD2 } },
    };
    made = BuildPatchedImage(binary, malformed, PatchedImageSource::Pristine);
    CHECK(!made.success && made.error == PatchedImageError::OriginalSizeMismatch);
    CHECK(made.appliedPatches == 0 && made.image.empty());

    malformed = { { 1, {}, {} } };
    made = BuildPatchedImage(binary, malformed, PatchedImageSource::Pristine);
    CHECK(!made.success && made.error == PatchedImageError::EmptyReplacement);

    malformed = {
        { std::numeric_limits<uint64_t>::max(), { 0x00 }, { 0xEE } },
    };
    made = BuildPatchedImage(binary, malformed, PatchedImageSource::Pristine);
    CHECK(!made.success && made.error == PatchedImageError::AddressRangeOverflow);

    malformed = { { 0x1000, { 0x00 }, { 0xEE } } };
    made = BuildPatchedImage(binary, malformed, PatchedImageSource::Pristine);
    CHECK(!made.success && made.error == PatchedImageError::RangeNotFileBacked);

    // A syntactically valid but semantically stale/corrupt `orig` field must
    // reject the complete restore before any private output is published.
    std::vector<PjPatch> wrongOriginal{
        { 1, { 0xFE }, { 0xD1 } },
    };
    made = BuildPatchedImage(binary, wrongOriginal, PatchedImageSource::Pristine);
    CHECK(!made.success && made.error == PatchedImageError::OriginalBytesMismatch);
    CHECK(made.failedPatch == 0 && made.failedAddress == 1);
    CHECK(made.appliedPatches == 0 && made.image.empty());
    CHECK(binary.bytes() == pristine);

    // No patches is a valid exact copy, not an error or an invented write.
    made = BuildPatchedImage(binary, {}, PatchedImageSource::Pristine);
    CHECK(made.success && made.appliedPatches == 0 && made.image == pristine);

    // AlreadyPatched is an assertion about the source, not permission to apply
    // missing patches. A pristine source plus non-noop records must fail closed.
    made = BuildPatchedImage(binary, valid, PatchedImageSource::AlreadyPatched);
    CHECK(!made.success && made.error == PatchedImageError::SourcePatchStateMismatch);
    CHECK(made.appliedPatches == 0 && made.image.empty());
    CHECK(binary.bytes() == pristine);
    PatchedImageResult removal = BuildImageAfterPatchRemoval(binary, valid, 0);
    CHECK(!removal.success &&
          removal.error == PatchedImageError::SourcePatchStateMismatch &&
          removal.image.empty());
    PatchRemovalSpanResult spanRemoval =
        CheckSpanMatchesFullImage(binary, valid, 0);
    CHECK(!spanRemoval.success &&
          spanRemoval.error == PatchedImageError::SourcePatchStateMismatch &&
          spanRemoval.bytes.empty());

    // Restoration commits the fully constructed candidate with one no-throw
    // swap. A malformed-size candidate is rejected before either bytes or the
    // image revision change.
    made = BuildPatchedImage(binary, valid, PatchedImageSource::Pristine);
    CHECK(made.success);
    const uint64_t revisionBefore = binary.imageRevision();
    std::vector<uint8_t> wrongSize(pristine.size() - 1, 0xCC);
    CHECK(!binary.commitPatchedImage(std::move(wrongSize)));
    CHECK(binary.bytes() == pristine && binary.imageRevision() == revisionBefore);
    CHECK(binary.commitPatchedImage(std::move(made.image)));
    CHECK(binary.imageRevision() == revisionBefore + 1);
    CHECK(binary.bytes().size() == pristine.size() &&
          binary.bytes()[0] == 0xA0 && binary.bytes()[1] == 0xA1 &&
          binary.bytes()[2] == 0xB2 && binary.bytes()[3] == 0xB3);

    // Revert is also a private transaction. Removing an early overlapping
    // record restores pristine bytes and then replays every survivor in order.
    PatchedImageResult removed = BuildImageAfterPatchRemoval(binary, valid, 0);
    CHECK(removed.success && removed.appliedPatches == 1);
    CHECK(removed.image.size() == pristine.size());
    if (removed.image.size() == pristine.size()) {
        CHECK(removed.image[0] == pristine[0] && removed.image[1] == pristine[1]);
        CHECK(removed.image[2] == 0xB2 && removed.image[3] == 0xB3);
    }
    CHECK(binary.bytes()[0] == 0xA0 && binary.bytes()[2] == 0xB2);
    spanRemoval = CheckSpanMatchesFullImage(binary, valid, 0);
    CHECK(spanRemoval.success && spanRemoval.appliedPatches == 1);
    CHECK(spanRemoval.address == 0);
    CHECK(spanRemoval.bytes == std::vector<uint8_t>({ 0x10, 0x11 }));

    removed = BuildImageAfterPatchRemoval(binary, valid, 1);
    CHECK(removed.success && removed.appliedPatches == 1);
    CHECK(removed.image.size() == pristine.size());
    if (removed.image.size() == pristine.size()) {
        CHECK(removed.image[0] == 0xA0 && removed.image[1] == 0xA1 &&
              removed.image[2] == 0xA2 && removed.image[3] == pristine[3]);
    }
    spanRemoval = CheckSpanMatchesFullImage(binary, valid, 1);
    CHECK(spanRemoval.success && spanRemoval.address == 2);
    CHECK(spanRemoval.bytes == std::vector<uint8_t>({ 0xA2, 0x13 }));
    removed = BuildImageAfterPatchRemoval(binary, valid, valid.size());
    CHECK(!removed.success && removed.error == PatchedImageError::RemovalIndexInvalid &&
          removed.image.empty());
    spanRemoval = CheckSpanMatchesFullImage(binary, valid, valid.size());
    CHECK(!spanRemoval.success &&
          spanRemoval.error == PatchedImageError::RemovalIndexInvalid &&
          spanRemoval.bytes.empty());

    // Source validation is global, not restricted to the removed span. Byte 3
    // belongs only to the surviving record and lies outside record 0; corrupting
    // it still rejects the span-only plan exactly like the full-image builder.
    const uint8_t corrupt = 0xEE;
    CHECK(binary.writeImage(3, &corrupt, 1) == 1);
    spanRemoval = CheckSpanMatchesFullImage(binary, valid, 0);
    CHECK(!spanRemoval.success &&
          spanRemoval.error == PatchedImageError::SourcePatchStateMismatch);

    // Removing a middle record replays survivors on both sides of it in their
    // original order. Two later, disjoint records shadow the removed span's
    // edges, while an earlier record becomes visible in the middle. Only that
    // two-byte changed center is returned.
    CHECK(binary.commitPatchedImage(std::vector<uint8_t>(pristine)));
    std::vector<PjPatch> layered{
        { 2, { 0x12, 0x13, 0x14 },
             { 0xA2, 0xA3, 0xA4 } },
        { 1, { 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 },
             { 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6 } },
        { 1, { 0x11, 0x12 }, { 0xC1, 0xC2 } },
        { 5, { 0x15, 0x16 }, { 0xE5, 0xE6 } },
    };
    made = BuildPatchedImage(binary, layered, PatchedImageSource::Pristine);
    CHECK(made.success);
    CHECK(binary.commitPatchedImage(std::move(made.image)));
    spanRemoval = CheckSpanMatchesFullImage(binary, layered, 1);
    CHECK(spanRemoval.success && spanRemoval.appliedPatches == 3);
    CHECK(spanRemoval.address == 3);
    CHECK(spanRemoval.bytes == std::vector<uint8_t>({ 0xA3, 0xA4 }));

    // Disjoint later survivors can collectively shadow the complete removed
    // record. Success with an empty payload is a distinguishable no-op and lets
    // the caller avoid a writeImage revision bump.
    CHECK(binary.commitPatchedImage(std::vector<uint8_t>(pristine)));
    std::vector<PjPatch> fullyShadowed{
        { 1, { 0x11, 0x12, 0x13, 0x14 },
             { 0xB1, 0xB2, 0xB3, 0xB4 } },
        { 1, { 0x11, 0x12 }, { 0xC1, 0xC2 } },
        { 3, { 0x13, 0x14 }, { 0xD3, 0xD4 } },
    };
    made = BuildPatchedImage(binary, fullyShadowed,
                             PatchedImageSource::Pristine);
    CHECK(made.success);
    CHECK(binary.commitPatchedImage(std::move(made.image)));
    spanRemoval = CheckSpanMatchesFullImage(binary, fullyShadowed, 0);
    CHECK(spanRemoval.success && spanRemoval.appliedPatches == 2);
    CHECK(spanRemoval.address == 1 && spanRemoval.bytes.empty());

    // Distinct PE section VAs may alias one raw file range. The full-image
    // builder naturally resolves overlap through file offsets; the span-only
    // planner must produce the same state and no-op result for the shadowed
    // first record.
    const std::string aliasPath = "patched_image_alias_fixture.bin";
    const std::vector<uint8_t> aliasPristine = BuildAliasedPE32();
    {
        std::ofstream file(aliasPath, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<const char*>(aliasPristine.data()),
                   static_cast<std::streamsize>(aliasPristine.size()));
    }
    BinaryFile aliasBinary;
    CHECK(aliasBinary.load(aliasPath));
    constexpr uint64_t aliasVA1 = 0x401010;
    constexpr uint64_t aliasVA2 = 0x402010;
    uint64_t aliasOffset1 = 0, aliasOffset2 = 0;
    CHECK(aliasBinary.vaToOffset(aliasVA1, aliasOffset1));
    CHECK(aliasBinary.vaToOffset(aliasVA2, aliasOffset2));
    CHECK(aliasOffset1 == 0x410 && aliasOffset2 == aliasOffset1);
    std::vector<PjPatch> aliases{
        { aliasVA1, { 0x31, 0x32 }, { 0xA1, 0xA2 } },
        { aliasVA2, { 0x31, 0x32 }, { 0xB1, 0xB2 } },
    };
    made = BuildPatchedImage(aliasBinary, aliases,
                             PatchedImageSource::Pristine);
    CHECK(made.success);
    CHECK(aliasBinary.commitPatchedImage(std::move(made.image)));
    spanRemoval = CheckSpanMatchesFullImage(aliasBinary, aliases, 0);
    CHECK(spanRemoval.success && spanRemoval.address == aliasVA1 &&
          spanRemoval.bytes.empty());
    spanRemoval = CheckSpanMatchesFullImage(aliasBinary, aliases, 1);
    CHECK(spanRemoval.success && spanRemoval.address == aliasVA2);
    CHECK(spanRemoval.bytes == std::vector<uint8_t>({ 0xA1, 0xA2 }));

    // Save As intentionally starts from that genuinely committed patched image.
    // Reapplying the persisted list is byte-identical/idempotent and keeps its
    // later-overlap-wins order; pristine validation remains restore-only.
    made = BuildPatchedImage(binary, fullyShadowed,
                             PatchedImageSource::AlreadyPatched);
    CHECK(made.success && made.appliedPatches == 3 && made.image == binary.bytes());
    made = BuildPatchedImage(binary, valid, PatchedImageSource::Pristine);
    CHECK(!made.success && made.error == PatchedImageError::OriginalBytesMismatch);

    std::remove(aliasPath.c_str());
    std::remove(path.c_str());
    if (failures) {
        std::fprintf(stderr, "%d patched-image check(s) failed\n", failures);
        return 1;
    }
    std::puts("patched image tests passed");
    return 0;
}
