#include "Core/AddressInspector.h"
#include "Core/BinaryFile.h"
#include "Core/XrefIndex.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #condition); ++g_fail; } } while (0)

static void put16(std::vector<uint8_t>& bytes, size_t offset, uint16_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

static void put32(std::vector<uint8_t>& bytes, size_t offset, uint32_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

static std::vector<uint8_t> buildPe32() {
    std::vector<uint8_t> bytes(0x600, 0);
    bytes[0] = 'M'; bytes[1] = 'Z';
    put32(bytes, 0x3c, 0x80);
    put32(bytes, 0x80, 0x00004550);
    const size_t coff = 0x84;
    put16(bytes, coff + 0, 0x014c);
    put16(bytes, coff + 2, 1);
    put16(bytes, coff + 16, 0xe0);
    put16(bytes, coff + 18, 0x102);
    const size_t optional = coff + 20;
    put16(bytes, optional + 0, 0x10b);
    put32(bytes, optional + 16, 0x1000);
    put32(bytes, optional + 28, 0x400000);
    put32(bytes, optional + 32, 0x1000);
    put32(bytes, optional + 36, 0x200);
    put32(bytes, optional + 56, 0x2000);
    put32(bytes, optional + 60, 0x400);
    put32(bytes, optional + 92, 16);
    const size_t section = optional + 0xe0;
    std::memcpy(bytes.data() + section, ".text", 5);
    put32(bytes, section + 8, 0x1000);
    put32(bytes, section + 12, 0x1000);
    put32(bytes, section + 16, 0x200);
    put32(bytes, section + 20, 0x400);
    put32(bytes, section + 36, 0x60000020u);
    bytes[0x420] = 0x90;
    return bytes;
}

static void writeBytes(const std::filesystem::path& path,
                       const std::vector<uint8_t>& bytes) {
    std::ofstream stream(path, std::ios::binary | std::ios::trunc);
    stream.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
}

static void testPeAndLiveIdentity(const std::filesystem::path& path) {
    writeBytes(path, buildPe32());
    BinaryFile binary;
    CHECK(binary.load(path.string()));
    CHECK(binary.format() == BinFormat::PE32);

    AddressLiveModuleSnapshot live;
    live.valid = true;
    live.base = 0x70000000;
    live.size = 0x2000;
    live.moduleName = "address_inspector_pe.bin";
    live.path = binary.path();
    live.contentHashValid = true;
    live.contentHash = 0xcafe;

    AddressInspectorSnapshots snapshots;
    snapshots.liveModule = &live;
    snapshots.staticContentHashValid = true;
    snapshots.staticContentHash = 0xcafe;

    const AddressInspection mapped = InspectAddress(binary, 0x401020, snapshots);
    CHECK(mapped.staticVA.valid && mapped.staticVA.value == 0x401020);
    CHECK(mapped.staticMapped);
    CHECK(mapped.rva.valid && mapped.rva.value == 0x1020);
    CHECK(mapped.fileOffset.valid && mapped.fileOffset.value == 0x420);
    CHECK(mapped.identity == AddressIdentityState::Match);
    CHECK(mapped.mappingConfidence == AddressMappingConfidence::High);
    CHECK(mapped.runtimeModuleOffset.valid && mapped.runtimeModuleOffset.value == 0x1020);
    CHECK(mapped.runtimeVA.valid && mapped.runtimeVA.value == 0x70001020);

    // Virtual section padding has a static/runtime identity but no file offset.
    const AddressInspection padding = InspectAddress(binary, 0x401300, snapshots);
    CHECK(padding.staticMapped && padding.rva.valid && padding.rva.value == 0x1300);
    CHECK(!padding.fileOffset.valid);
    CHECK(padding.runtimeVA.valid && padding.runtimeVA.value == 0x70001300);

    // An exact identity is not permission to escape the supplied live extent.
    live.size = 0x1000;
    const AddressInspection outOfBounds = InspectAddress(binary, 0x401020, snapshots);
    CHECK(outOfBounds.identity == AddressIdentityState::Match);
    CHECK(!outOfBounds.runtimeVA.valid && !outOfBounds.runtimeModuleOffset.valid);
    CHECK(outOfBounds.identityEvidence.find("outside") != std::string::npos);

    live.size = 0x2000;
    live.contentHash = 0xbeef;
    const AddressInspection mismatch = InspectAddress(binary, 0x401020, snapshots);
    CHECK(mismatch.identity == AddressIdentityState::Mismatch);
    CHECK(mismatch.mappingConfidence == AddressMappingConfidence::None);
    CHECK(!mismatch.runtimeVA.valid);

    live.contentHash = 0xcafe;
    live.base = (std::numeric_limits<uint64_t>::max)() - 0x1000;
    const AddressInspection overflow = InspectAddress(binary, 0x401020, snapshots);
    CHECK(overflow.identity == AddressIdentityState::Match);
    CHECK(!overflow.runtimeVA.valid);
    CHECK(overflow.identityEvidence.find("overflows") != std::string::npos);

    // Without common hashes, distinct module identities fail closed.
    live.base = 0x70000000;
    live.contentHashValid = false;
    live.path = "C:/different/not_the_binary.dll";
    snapshots.staticContentHashValid = false;
    const AddressInspection pathMismatch = InspectAddress(binary, 0x401020, snapshots);
    CHECK(pathMismatch.identity == AddressIdentityState::Mismatch);
    CHECK(!pathMismatch.runtimeVA.valid);
}

static void testZeroOverridesPatchesAndXrefs(const std::filesystem::path& path) {
    writeBytes(path, { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 });
    BinaryFile binary;
    CHECK(binary.loadRaw(path.string(), 0));

    ProjectState project;
    project.hash = 0x4242;
    project.names[1] = "typed_byte";
    project.comments[1] = "overlap site";

    PjFunctionOverride function;
    function.address = 0;
    function.action = PjFunctionAction::Define;
    function.exactExtentValid = true;
    function.exactSize = 4;
    function.noreturn = PjOverrideBool::False;
    function.callingConvention = "__cdecl";
    function.prototype = "int entry(void)";
    project.functionOverrides.push_back(function);
    project.dataOverrides.push_back({ 0, 2, PjDataKind::String, "char[2]" });

    project.patches.push_back({ 0, { 0x10, 0x11 }, { 0xa0, 0xa1 } });
    project.patches.push_back({ 1, { 0x11 },       { 0xb1 } });
    project.patches.push_back({ 0, { 0x10, 0x11 }, { 0xc0, 0xc1 } });

    XrefIndex xrefs;
    xrefs.toTarget[1] = { 0x10, 0x20, 0x30, 0x40 };
    xrefs.accessOf[0x10] = 0;
    xrefs.accessOf[0x20] = 1;
    xrefs.accessOf[0x30] = 2;

    CodeDataMap classifications;
    classifications.imageRevision = binary.imageRevision();
    classifications.spans.push_back({ 0, 8, CodeDataKind::Code, 1,
                                      CodeDataConfidence::Medium,
                                      "reachable from raw entry" });

    AddressLiveModuleSnapshot live;
    live.valid = true;
    live.base = 0;                         // valid runtime address zero
    live.size = 8;
    live.moduleName = path.filename().string();
    live.contentHashValid = true;
    live.contentHash = project.hash;

    AddressInspectorSnapshots snapshots;
    snapshots.project = &project;
    snapshots.xrefs = &xrefs;
    snapshots.classification = &classifications;
    snapshots.liveModule = &live;

    const AddressInspection zero = InspectAddress(binary, 0, snapshots);
    CHECK(zero.staticVA.valid && zero.staticVA.value == 0);
    CHECK(zero.staticMapped);
    CHECK(zero.rva.valid && zero.rva.value == 0);
    CHECK(zero.fileOffset.valid && zero.fileOffset.value == 0);
    CHECK(zero.runtimeVA.valid && zero.runtimeVA.value == 0);
    CHECK(zero.runtimeModuleOffset.valid && zero.runtimeModuleOffset.value == 0);
    CHECK(zero.functionOverride.valid && zero.functionOverride.exactStart);

    const AddressInspection inspected = InspectAddress(binary, 1, snapshots);
    CHECK(inspected.functionOverride.valid && !inspected.functionOverride.exactStart);
    CHECK(inspected.functionOverride.offset == 1);
    CHECK(inspected.functionOverride.value.prototype == "int entry(void)");
    CHECK(inspected.dataOverride.valid && inspected.dataOverride.offset == 1);
    CHECK(inspected.dataOverride.value.type == "char[2]");
    CHECK(inspected.derivedClassification.valid);
    CHECK(inspected.derivedClassification.kind == CodeDataKind::Code);
    CHECK(inspected.effectiveClassification.valid && inspected.effectiveClassification.analyst);
    CHECK(inspected.effectiveClassification.kind == CodeDataKind::String);
    CHECK(inspected.effectiveClassification.type == "char[2]");
    CHECK(inspected.userNameValid && inspected.userName == "typed_byte");
    CHECK(inspected.userCommentValid && inspected.userComment == "overlap site");

    CHECK(inspected.xrefs.valid && inspected.xrefs.total == 4);
    CHECK(inspected.xrefs.readers == 1);
    CHECK(inspected.xrefs.writers == 1);
    CHECK(inspected.xrefs.addressReferences == 1);
    CHECK(inspected.xrefs.controlFlow == 1);

    CHECK(inspected.patches.snapshotValid && inspected.patches.patched);
    CHECK(inspected.patches.hits.size() == 3);
    if (inspected.patches.hits.size() == 3) {
        CHECK(inspected.patches.hits[0].applicationIndex == 0);
        CHECK(inspected.patches.hits[1].applicationIndex == 1);
        CHECK(inspected.patches.hits[2].applicationIndex == 2);
        CHECK(!inspected.patches.hits[0].winner);
        CHECK(!inspected.patches.hits[1].winner);
        CHECK(inspected.patches.hits[2].winner);
    }
    CHECK(inspected.patches.pristineByteValid && inspected.patches.pristineByte == 0x11);
    CHECK(inspected.patches.effectiveByteValid && inspected.patches.effectiveByte == 0xc1);

    // A derived snapshot from a prior image revision is surfaced, not trusted.
    classifications.imageRevision = binary.imageRevision() + 1;
    const AddressInspection stale = InspectAddress(binary, 3, snapshots);
    CHECK(!stale.derivedClassification.valid && stale.derivedClassification.staleSnapshot);
}

int main() {
    const std::filesystem::path temp = std::filesystem::temp_directory_path();
    const std::filesystem::path pe = temp / "address_inspector_pe.bin";
    const std::filesystem::path raw = temp / "address_inspector_raw.bin";

    testPeAndLiveIdentity(pe);
    testZeroOverridesPatchesAndXrefs(raw);

    std::error_code ignored;
    std::filesystem::remove(pe, ignored);
    std::filesystem::remove(raw, ignored);

    if (g_fail == 0) std::printf("ALL ADDRESS INSPECTOR TESTS PASSED\n");
    else std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
