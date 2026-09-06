#include "Core/BinaryFile.h"
#include "Core/XrefIndex.h"
#include "Disasm/IDisassembler.h"

#include <cstdio>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond, message) do { if (!(cond)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, message); ++g_fail; \
} } while (0)

struct FarTargetDisassembler final : IDisassembler {
    Instruction instruction;

    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "real-mode-alias-fixture"; }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& out) override {
        if (!data || !size) return false;
        out = instruction;
        out.address = va;
        out.length = 1;
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t va, size_t maxInstructions) override {
        std::vector<Instruction> result;
        if (!maxInstructions || maxInstructions >= 1) {
            Instruction decoded;
            if (decodeOne(data, size, va, decoded)) result.push_back(std::move(decoded));
        }
        return result;
    }
};

int main() {
    const std::string path = "binaryfile_real_mode_fixture.bin";
    const std::vector<uint8_t> bytes(0x10000, 0);
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        CHECK(output.good(), "write the 64-KiB Raw firmware fixture");
    }

    BinaryFile firmware;
    CHECK(firmware.loadRaw(path, 0xFFFF0000ull),
          "load a 64-KiB firmware image at the top of the 32-bit address space");

    uint64_t target = 0;
    CHECK(firmware.resolveRealModeAlias(0xF000, 0xFFF0, target),
          "resolve the reset-vector segment:offset through the top-mapped alias");
    CHECK(target == 0xFFFFFFF0ull,
          "the reset-vector alias resolves to the final 16 bytes below 4 GiB");

    Instruction farJump;
    farJump.address = 0xFFFFFFF0ull;
    farJump.mnemonic = "ljmp";
    farJump.isBranch = true;
    farJump.flow.kind = FlowKind::UnconditionalBranch;
    farJump.farTarget.valid = true;
    farJump.farTarget.segment = 0xF000;
    farJump.farTarget.offset = 0xFFF0;
    farJump.farTarget.offsetBits = 16;
    CHECK(firmware.resolveInstructionTarget(farJump, target),
          "resolve a decoder-preserved far target through BinaryFile");
    CHECK(target == 0xFFFFFFF0ull,
          "instruction target resolution retains the top-of-4-GiB alias");

    size_t available = 0;
    const uint8_t* mapped = firmware.ptrFromVA(0xFFFF0000ull, available);
    CHECK(mapped && available >= 1, "obtain one mapped byte for the xref sweep");
    FarTargetDisassembler farDecoder;
    farDecoder.instruction = farJump;
    XrefIndex defaultXrefs;
    BuildXrefInto(defaultXrefs, mapped, 1, 0xFFFF0000ull, farDecoder);
    CHECK(defaultXrefs.sources(0xFFFFFFF0ull) == nullptr,
          "decoder-only xref behavior does not invent a linear far target");

    const XrefTargetResolver imageTarget =
        [&firmware](const Instruction& instruction, uint64_t& resolved) {
            return firmware.resolveInstructionTarget(instruction, resolved);
        };
    XrefIndex resolvedXrefs;
    BuildXrefInto(resolvedXrefs, mapped, 1, 0xFFFF0000ull, farDecoder,
                  nullptr, imageTarget);
    FinalizeXrefIndex(resolvedXrefs);
    const std::vector<uint64_t>* sources = resolvedXrefs.sources(0xFFFFFFF0ull);
    CHECK(sources && sources->size() == 1 && (*sources)[0] == 0xFFFF0000ull,
          "image-aware whole-program xrefs index the top-mapped far target");

    std::vector<uint64_t> targetedHits;
    CHECK(FindRefsInBuffer(mapped, 1, 0xFFFF0000ull, 0xFFFFFFF0ull,
                           farDecoder, targetedHits, 8, imageTarget),
          "targeted image-aware xref search completes");
    CHECK(targetedHits.size() == 1 && targetedHits[0] == 0xFFFF0000ull,
          "targeted xref search finds the resolved far target");

    BinaryFile zeroMapped;
    CHECK(zeroMapped.loadRaw(path, 0), "load the same Raw image at VA zero");
    CHECK(zeroMapped.resolveRealModeAlias(0, 0, target),
          "a mapped real-mode target at numeric VA zero is valid");
    CHECK(target == 0, "real-mode alias validity is independent of the numeric VA");

    Instruction directZero;
    directZero.address = 0x10;
    directZero.mnemonic = "jmp";
    directZero.isBranch = true;
    directZero.branchTargetValid = true;
    directZero.branchTarget = 0;
    directZero.flow.kind = FlowKind::UnconditionalBranch;
    directZero.flow.directTargetValid = true;
    directZero.flow.directTarget = 0;
    CHECK(zeroMapped.resolveInstructionTarget(directZero, target),
          "a decoder-supplied direct target at VA zero remains valid");
    CHECK(target == 0, "direct target resolution does not use zero as a sentinel");

    std::remove(path.c_str());
    const uint8_t* originalBytes = zeroMapped.bytes().data();
    const std::string originalPath = zeroMapped.path();
    const uint64_t originalHash = zeroMapped.contentHash();
    const uint64_t originalRevision = zeroMapped.imageRevision();
    CHECK(zeroMapped.remapRaw(0xFFFF0000ull, 0xFFFFFFF0ull, true,
          {{0xFFFFFFF0ull, "reset", "saved root"},
           {0xFFFF0010ull, "start", "saved root"},
           {0xFFFFFFF0ull, "reset", "duplicate"}}),
          "restore a complete Raw mapping after the source file is removed");
    CHECK(zeroMapped.bytes().data() == originalBytes &&
          zeroMapped.contentHash() == originalHash && zeroMapped.path() == originalPath,
          "remap retains the original byte allocation, pristine identity, and durable path");
    CHECK(zeroMapped.imageRevision() > originalRevision &&
          zeroMapped.entryPointVA() == 0xFFFFFFF0ull && zeroMapped.rawEntryExplicit(),
          "remap advances the analysis revision and restores the explicit entry");
    CHECK(zeroMapped.analysisLandmarks().size() == 2 &&
          zeroMapped.analysisLandmarks()[0].address == 0xFFFF0010ull,
          "remap normalizes and deduplicates the saved roots");
    uint64_t offset = 0;
    CHECK(zeroMapped.vaToOffset(0xFFFFFFF0ull, offset) && offset == 0xFFF0ull &&
          zeroMapped.offsetToVA(offset, target) && target == 0xFFFFFFF0ull,
          "the restored mapping retains exact VA/file-offset round trips");
    const uint64_t mappedRevision = zeroMapped.imageRevision();
    CHECK(!zeroMapped.remapRaw(std::numeric_limits<uint64_t>::max(), 0, false, {}),
          "remap rejects an overflowing byte extent");
    CHECK(!zeroMapped.remapRaw(0, bytes.size(), true, {}),
          "remap rejects a one-past-end entry");
    CHECK(!zeroMapped.remapRaw(0, 0, true, {{bytes.size(), "outside", ""}}),
          "remap rejects unmapped roots");
    CHECK(!zeroMapped.remapRaw(0, 0, true, {{0, "", ""}}),
          "remap rejects unnamed roots");
    CHECK(zeroMapped.imageRevision() == mappedRevision &&
          zeroMapped.imageBase() == 0xFFFF0000ull &&
          zeroMapped.entryPointVA() == 0xFFFFFFF0ull &&
          zeroMapped.analysisLandmarks().size() == 2,
          "invalid remaps preserve the entire previously accepted mapping");
    CHECK(zeroMapped.remapRaw(0, 0, true, {{0, "zero", ""}}) &&
          zeroMapped.hasEntryPoint() && zeroMapped.entryPointVA() == 0,
          "remap preserves an authoritative entry and root at VA zero");
    CHECK(zeroMapped.remapRaw(0x1000, 0, false, {}) &&
          !zeroMapped.hasEntryPoint() && !zeroMapped.rawEntryExplicit() &&
          zeroMapped.analysisLandmarks().empty(),
          "remap can explicitly clear the previous entry and root set");
    BinaryFile liveRaw;
    CHECK(liveRaw.loadFromMemory(bytes, 0, "live raw") &&
          !liveRaw.remapRaw(0x1000, 0x1000, true, {}),
          "remap never changes a live capture's address identity");
    if (g_fail) {
        std::printf("binaryfile_real_mode_test: %d failure(s)\n", g_fail);
        return 1;
    }
    std::printf("binaryfile_real_mode_test: all checks passed\n");
    return 0;
}
