// Exact raw mapping identity round-trip: the sidecar must be sufficient to
// stage the same BinaryFile base, explicit VA-0 entry, and named roots on reopen.

#include "Core/BinaryFile.h"
#include "Core/Project.h"
#include "Disasm/IDisassembler.h"

#include <cstdio>
#include <fstream>
#include <limits>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

int main() {
    const char* path = "raw_project_reopen.bin";
    std::vector<uint8_t> bytes(0x100, 0);
    bytes[0] = 0x00; bytes[1] = 0xBF; // Thumb NOP at the legitimate VA-0 entry
    { std::ofstream out(path, std::ios::binary); out.write((const char*)bytes.data(), bytes.size()); }

    ProjectState saved;
    saved.hash = 0x1234;
    saved.binaryPath = path;
    saved.arch = "Thumb/Thumb-2";
    saved.engine = "Capstone";
    saved.rawMappingSaved = true;
    saved.rawImageBase = 0;
    saved.rawEntry = 0;
    saved.rawEntryExplicit = true;
    saved.rawBigEndian = true;
    DecoderFeatures savedFeatures;
    savedFeatures.riscvCompressed = false;
    savedFeatures.armV8 = true;
    savedFeatures.armMClass = true;
    savedFeatures.mipsMicro = true;
    saved.rawDecoderFeatureBits = DecoderFeatureBits(savedFeatures);
    saved.rawRiscvCompressed = savedFeatures.riscvCompressed;
    saved.rawLandmarks.push_back({0, "reset_entry", "explicit zero entry"});
    saved.rawLandmarks.push_back({0x40, "irq_handler", "analyst root"});

    ProjectState reopened;
    CHECK(DeserializeProject(SerializeProject(saved), reopened));
    Arch arch = Arch::X64;
    CHECK(ArchFromName(reopened.arch.c_str(), arch) && arch == Arch::THUMB);
    CHECK(ArchMappingRangeFits(arch, reopened.rawImageBase, bytes.size()));
    DecoderConfig reopenedConfig;
    reopenedConfig.arch = arch;
    reopenedConfig.byteOrder = reopened.rawBigEndian
                             ? ByteOrder::Big : ByteOrder::Little;
    CHECK(DecoderFeaturesFromBits(reopened.rawDecoderFeatureBits,
                                  reopenedConfig.features));
    CHECK(reopenedConfig.byteOrder == ByteOrder::Big);
    CHECK(reopenedConfig.features == savedFeatures);
    CHECK(!reopened.rawRiscvCompressed);

    BinaryFile staged;
    CHECK(staged.loadRaw(path, reopened.rawImageBase));
    CHECK(!reopened.rawEntryExplicit || staged.setRawEntryPointVA(reopened.rawEntry));
    std::vector<AnalysisLandmark> landmarks;
    for (const PjRawLandmark& root : reopened.rawLandmarks)
        landmarks.push_back({root.address, root.name, root.evidence});
    CHECK(staged.setAnalysisLandmarks(std::move(landmarks)));

    CHECK(staged.format() == BinFormat::Raw && staged.imageBase() == 0);
    CHECK(staged.rawEntryExplicit() && staged.hasEntryPoint() && staged.entryPointVA() == 0);
    CHECK(staged.analysisLandmarks().size() == 2);
    CHECK(staged.analysisLandmarks()[0].address == 0 &&
          staged.analysisLandmarks()[0].name == "reset_entry");
    CHECK(staged.analysisLandmarks()[1].address == 0x40 &&
          staged.analysisLandmarks()[1].name == "irq_handler");

    // Runtime Raw metadata and the sidecar schema share the same input bound.
    // Apply it before deduplication so a huge vector of identical roots cannot
    // create state which saves successfully but is rejected on reopen.
    std::vector<AnalysisLandmark> bounded(
        BinaryFile::kMaxAnalysisLandmarks,
        AnalysisLandmark{0, "bounded_root", "duplicate fixture"});
    CHECK(staged.setAnalysisLandmarks(std::move(bounded)));
    CHECK(staged.analysisLandmarks().size() == 1 &&
          staged.analysisLandmarks()[0].name == "bounded_root");
    std::vector<AnalysisLandmark> tooMany(
        BinaryFile::kMaxAnalysisLandmarks + 1,
        AnalysisLandmark{0, "rejected_root", "duplicate fixture"});
    CHECK(!staged.setAnalysisLandmarks(std::move(tooMany)));
    CHECK(staged.analysisLandmarks().size() == 1 &&
          staged.analysisLandmarks()[0].name == "bounded_root");
    uint64_t off = (std::numeric_limits<uint64_t>::max)();
    CHECK(staged.vaToOffset(0, off) && off == 0);
    size_t avail = 0;
    CHECK(staged.ptrFromVA(0, avail) && avail == bytes.size());

    // A stale/corrupt optional mapping is rejectable without making the file
    // itself unopenable: the initially staged raw fallback remains valid and the
    // caller can discard the sidecar metadata.
    ProjectState corrupt = reopened;
    corrupt.rawImageBase = 0x100000000ull; // impossible in A32/Thumb
    corrupt.rawEntry = 0x100000000ull;
    ProjectState corruptRt;
    CHECK(DeserializeProject(SerializeProject(corrupt), corruptRt));
    CHECK(!ArchMappingRangeFits(arch, corruptRt.rawImageBase, bytes.size()));
    BinaryFile safeFallback;
    CHECK(safeFallback.load(path) && safeFallback.format() == BinFormat::Raw &&
          safeFallback.imageBase() == 0);

    std::remove(path);
    if (!g_fail) std::puts("raw_project_reopen_test: all checks passed");
    return g_fail ? 1 : 0;
}
