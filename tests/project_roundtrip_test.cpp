//
// project_roundtrip_test.cpp
// Off-target unit test for the project sidecar (de)serialization in
// src/Core/Project.cpp, focused on the per-project engine + arch persistence
// added so a binary reopens with its last-used disassembler/architecture, plus a
// general round-trip of the existing annotation fields (64-bit address precision).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\project_roundtrip_test.cpp src\Core\Project.cpp src\Core\Json.cpp
//   .\project_roundtrip_test.exe
//
#include "Core/Project.h"
#include "Core/PatchSet.h"
#include "Core/Json.h"
#include "Disasm/Assembler.h"
#include "Disasm/IDisassembler.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

namespace fs = std::filesystem;

class ScopedProjectsDir {
public:
    ScopedProjectsDir() {
        if (const char* value = std::getenv("DS_PROJECTS_DIR")) {
            hadOld_ = true;
            old_ = value;
        }
    }
    ~ScopedProjectsDir() { restore(); }

    bool set(const fs::path& path) {
#ifdef _WIN32
        return _putenv_s("DS_PROJECTS_DIR", path.string().c_str()) == 0;
#else
        return ::setenv("DS_PROJECTS_DIR", path.string().c_str(), 1) == 0;
#endif
    }

    void restore() {
        if (restored_) return;
#ifdef _WIN32
        _putenv_s("DS_PROJECTS_DIR", hadOld_ ? old_.c_str() : "");
#else
        if (hadOld_) ::setenv("DS_PROJECTS_DIR", old_.c_str(), 1);
        else ::unsetenv("DS_PROJECTS_DIR");
#endif
        restored_ = true;
    }

private:
    bool hadOld_ = false;
    bool restored_ = false;
    std::string old_;
};

int main() {
    ProjectState st;
    st.hash       = 0xDEADBEEFCAFEF00Dull;     // exercise full 64-bit precision
    st.binaryPath = "C:/work/blob.bin";
    st.arch       = "ARM64";
    st.engine     = "Capstone";
    st.name       = "blob.bin";
    st.lastCursor = 0x1400123456ull;
    st.lastCursorValid = true;
    st.notes      = "raw firmware @ 0";
    st.rawMappingSaved = true;
    st.rawImageBase = 0;
    st.rawEntry = 0;
    st.rawEntryExplicit = true;
    st.rawBigEndian = true;
    st.rawRiscvCompressed = false;
    DecoderFeatures persistedRawFeatures;
    persistedRawFeatures.riscvCompressed = false;
    persistedRawFeatures.armV8 = true;
    persistedRawFeatures.armMClass = true;
    persistedRawFeatures.mipsMicro = true;
    st.rawDecoderFeatureBits = DecoderFeatureBits(persistedRawFeatures);
    st.rawLandmarks.push_back({0, "reset_entry", "analyst-selected VA 0 root"});
    st.rawLandmarks.push_back({0x80, "irq_handler", "firmware vector evidence"});
    st.comments[0x1400001000ull] = "entry";
    st.names[0x1400002000ull]    = "decrypt";
    st.functionOverrides.push_back({ 0, PjFunctionAction::Define, true, 0x40,
                                     PjOverrideBool::False, "__fastcall",
                                     "bool reset_entry(uint32_t reason)", PjFunctionMode::Thumb });
    st.functionOverrides.push_back({ 0x1400002800ull, PjFunctionAction::Undefine });
    st.dataOverrides.push_back({ 0, 0x10, PjDataKind::Code, "thumb_code" });
    st.dataOverrides.push_back({ 0x1400003000ull, 0x20, PjDataKind::PointerTable,
                                 "const void*" });
    st.bookmarks.push_back({ 0x1400003000ull, "table" });
    st.breakpoints.push_back(0x1400004000ull);
    st.bpConditions[0x1400004000ull] = "x0 == 0";
    st.patchSets.push_back({ 7, "Global gate only", true });
    st.patchSets.push_back({ 11, "Global + feature gates", false });
    st.patches.push_back({ 0x1400005000ull, { 0x01, 0x02 },
                           { 0x90, 0x90 }, 7 });
    st.watches.push_back("rax");
    st.watches.push_back("[rsp+8]");
    st.labels.push_back({ "java_method", "Crackme.check:(Ljava/lang/String;)Z", "check_password", 0.8f, "analyst label" });
    st.listingLayoutSaved = true;
    st.peHeaderVisible = true;
    st.peHeaderFolded = false;
    st.listingSections.push_back({ 0x1000, ".text", true, false });
    st.listingSections.push_back({ 0x3000, ".rsrc", true, true });
    st.connection.enabled = true;
    st.connection.authEnabled = true;
    st.connection.accessToken = "tok";
    st.connectionEvents.push_back({ "event", "tool", "proj", "artifact", "0x1400002000",
                                    "breakpoint.hit", "{\"tid\":7}", "2026-06-12T00:00:00Z" });

    std::string text = SerializeProject(st);
    CHECK(text.find("\"version\": 5") != std::string::npos);
    CHECK(text.find("\"featureBits\": 14") != std::string::npos);
    ProjectState rt;
    CHECK(DeserializeProject(text, rt));

    // The new per-project disassembler settings survive the round-trip.
    CHECK(rt.engine == "Capstone");
    CHECK(rt.arch   == "ARM64");

    // ArchFromName / EngineFromName reconstruct the enums the App reapplies.
    Arch a; CHECK(ArchFromName(rt.arch.c_str(), a) && a == Arch::ARM64);
    Engine e; CHECK(EngineFromName(rt.engine.c_str(), e) && e == Engine::Capstone);
    CHECK(std::string(ArchName(Arch::ARM64)) == "ARM64");
    CHECK(std::string(EngineNameOf(Engine::Capstone)) == "Capstone");
    // Round-trip every arch name through ArchFromName.
    for (Arch x : { Arch::X86_16, Arch::X86, Arch::X64, Arch::ARM, Arch::THUMB, Arch::ARM64, Arch::MIPS,
                    Arch::MIPS64, Arch::PPC, Arch::PPC64, Arch::RISCV32, Arch::RISCV64, Arch::JVM }) {
        Arch back; CHECK(ArchFromName(ArchName(x), back) && back == x);
    }
    Arch thumbAlias;
    CHECK(ArchFromName("Thumb", thumbAlias) && thumbAlias == Arch::THUMB);
    CHECK(ArchFromName("Thumb-2", thumbAlias) && thumbAlias == Arch::THUMB);
    CHECK(ArchIsX86(Arch::X86_16));
    CHECK(ArchIsX86(Arch::X86));
    CHECK(ArchIsX86(Arch::X64));
    CHECK(!ArchIsX86(Arch::ARM));
    CHECK(!ArchIsX86_32Or64(Arch::X86_16));
    CHECK(ArchIsX86_32Or64(Arch::X86));
    CHECK(ArchIsX86_32Or64(Arch::X64));
    CHECK(ArchIsArm(Arch::ARM) && ArchIsArm(Arch::THUMB) && ArchIsArm(Arch::ARM64));
    CHECK(ArchSupportsDecompiler(Arch::THUMB)); // conservative raw statements; deep flow stays x86-only
    CHECK(!ArchSupportsDebugger(Arch::ARM64));
    CHECK(ArchSupportsAssembler(Arch::ARM) && ArchSupportsAssembler(Arch::THUMB) &&
          ArchSupportsAssembler(Arch::ARM64));
    CHECK(EffectiveDisasmEngine(Engine::Zydis, Arch::ARM) == Engine::Capstone);
    CHECK(AnalysisIsaSignature(Arch::ARM, Engine::Zydis) ==
          AnalysisIsaSignature(Arch::ARM, Engine::Capstone));
    CHECK(AnalysisIsaSignature(Arch::ARM, Engine::Zydis) !=
          AnalysisIsaSignature(Arch::THUMB, Engine::Zydis));
    CHECK(AnalysisIsaSignature(Arch::X64, Engine::Zydis) !=
          AnalysisIsaSignature(Arch::X64, Engine::Capstone));
    CHECK(ArchInvalidDecodeWidth(Arch::ARM) == 4 &&
          ArchInvalidDecodeWidth(Arch::THUMB) == 2 &&
          ArchInvalidDecodeWidth(Arch::ARM64) == 4 &&
          ArchInvalidDecodeWidth(Arch::MIPS64) == 4 &&
          ArchInvalidDecodeWidth(Arch::PPC) == 4 &&
          ArchInvalidDecodeWidth(Arch::RISCV32) == 2 &&
          ArchInvalidDecodeWidth(Arch::RISCV64) == 2);
    CHECK(ArchMappingRangeFits(Arch::THUMB, 0, 0x1000));
    CHECK(ArchMappingRangeFits(Arch::ARM, 0xFFFF0000ull, 0x10000));
    CHECK(!ArchMappingRangeFits(Arch::ARM, 0x100000000ull, 4));
    CHECK(!ArchMappingRangeFits(Arch::THUMB, 0xFFFFFFFEull, 4));
    CHECK(ArchMappingRangeFits(Arch::ARM64, 0x140000000ull, 0x1000));
    CHECK(!ArchMappingRangeFits(Arch::MIPS, 0x100000000ull, 4));
    CHECK(!ArchMappingRangeFits(Arch::PPC, 0xFFFFFFFCull, 8));
    CHECK(!ArchMappingRangeFits(Arch::RISCV32, 0x100000000ull, 2));
    CHECK(ArchMappingRangeFits(Arch::MIPS64, 0x100000000ull, 4));
    DecoderConfig baseRv;
    baseRv.arch = Arch::RISCV64;
    baseRv.features.riscvCompressed = false;
    CHECK(ArchInstructionAlignment(baseRv) == 4);
    baseRv.features.riscvCompressed = true;
    CHECK(ArchInstructionAlignment(baseRv) == 2);
    DecoderFeatures allFeatures;
    allFeatures.riscvCompressed = true;
    allFeatures.armV8 = true;
    allFeatures.armMClass = true;
    allFeatures.mipsMicro = true;
    CHECK(DecoderFeatureBits(allFeatures) == kKnownDecoderFeatureBits);
    DecoderFeatures decodedFeatures;
    decodedFeatures.armV8 = false;
    CHECK(DecoderFeaturesFromBits(kKnownDecoderFeatureBits, decodedFeatures));
    CHECK(decodedFeatures == allFeatures);
    const DecoderFeatures unchanged = decodedFeatures;
    CHECK(!DecoderFeaturesFromBits(kKnownDecoderFeatureBits | (1u << 31),
                                   decodedFeatures));
    CHECK(decodedFeatures == unchanged);

    // Exact architectural NOPs and fixed-width padding refusal.
    std::vector<uint8_t> nops;
    CHECK(ArchitectureNopFill(Arch::ARM, 4, nops) &&
          nops == std::vector<uint8_t>({0x00,0xF0,0x20,0xE3}));
    CHECK(ArchitectureNopFill(Arch::THUMB, 4, nops) &&
          nops == std::vector<uint8_t>({0x00,0xBF,0x00,0xBF}));
    CHECK(ArchitectureNopFill(Arch::ARM64, 4, nops) &&
          nops == std::vector<uint8_t>({0x1F,0x20,0x03,0xD5}));
    CHECK(!ArchitectureNopFill(Arch::ARM, 2, nops));
    std::vector<uint8_t> encoded = {0x01,0x20};
    CHECK(PadWithArchitectureNops(Arch::THUMB, encoded, 4) &&
          encoded == std::vector<uint8_t>({0x01,0x20,0x00,0xBF}));
    encoded = {0x00,0x00};
    CHECK(!PadWithArchitectureNops(Arch::ARM64, encoded, 4));
    Arch junk; CHECK(!ArchFromName("nonsense", junk));

    // The rest of the state still round-trips (incl. 64-bit hash/cursor/addresses).
    CHECK(rt.hash == st.hash);
    CHECK(rt.lastCursor == st.lastCursor);
    CHECK(rt.lastCursorValid == st.lastCursorValid);
    CHECK(rt.notes == st.notes);
    CHECK(rt.rawMappingSaved && rt.rawImageBase == 0 && rt.rawEntryExplicit && rt.rawEntry == 0 &&
          rt.rawBigEndian && !rt.rawRiscvCompressed &&
          rt.rawDecoderFeatureBits == DecoderFeatureBits(persistedRawFeatures));
    DecoderFeatures reopenedRawFeatures;
    CHECK(DecoderFeaturesFromBits(rt.rawDecoderFeatureBits, reopenedRawFeatures));
    CHECK(reopenedRawFeatures == persistedRawFeatures);
    CHECK(rt.rawLandmarks.size() == 2 && rt.rawLandmarks[0].address == 0 &&
          rt.rawLandmarks[0].name == "reset_entry" && rt.rawLandmarks[1].address == 0x80);
    CHECK(rt.comments.size() == 1 && rt.comments[0x1400001000ull] == "entry");
    CHECK(rt.names.size() == 1 && rt.names[0x1400002000ull] == "decrypt");
    CHECK(rt.functionOverrides.size() == 2);
    CHECK(rt.functionOverrides[0].address == 0 &&
          rt.functionOverrides[0].action == PjFunctionAction::Define &&
          rt.functionOverrides[0].exactExtentValid && rt.functionOverrides[0].exactSize == 0x40 &&
          rt.functionOverrides[0].noreturn == PjOverrideBool::False &&
          rt.functionOverrides[0].callingConvention == "__fastcall" &&
          rt.functionOverrides[0].prototype == "bool reset_entry(uint32_t reason)" &&
          rt.functionOverrides[0].mode == PjFunctionMode::Thumb);
    CHECK(rt.functionOverrides[1].address == 0x1400002800ull &&
          rt.functionOverrides[1].action == PjFunctionAction::Undefine);
    CHECK(rt.dataOverrides.size() == 2 && rt.dataOverrides[0].address == 0 &&
          rt.dataOverrides[0].size == 0x10 && rt.dataOverrides[0].kind == PjDataKind::Code &&
          rt.dataOverrides[0].type == "thumb_code" &&
          rt.dataOverrides[1].kind == PjDataKind::PointerTable);
    CHECK(rt.bookmarks.size() == 1 && rt.bookmarks[0].address == 0x1400003000ull);
    CHECK(rt.breakpoints.size() == 1 && rt.breakpoints[0] == 0x1400004000ull);
    CHECK(rt.bpConditions[0x1400004000ull] == "x0 == 0");
    CHECK(rt.patches.size() == 1 && rt.patches[0].address == 0x1400005000ull
          && rt.patches[0].bytes.size() == 2 && rt.patches[0].bytes[0] == 0x90
          && rt.patches[0].patchSetId == 7);
    CHECK(rt.patchSets.size() == 2 && rt.patchSets[0].id == 7 &&
          rt.patchSets[0].name == "Global gate only" &&
          rt.patchSets[0].enabled && rt.patchSets[1].id == 11 &&
          !rt.patchSets[1].enabled);

    // Patch vector order is semantic: later entries win where patches overlap.
    // Deliberately append the higher-address patch first so address sorting would
    // reverse the intended result after a save/reopen round-trip.
    ProjectState patchOrder;
    patchOrder.hash = 0xA11CE;
    patchOrder.patches.push_back({ 0x1002, { 0x02, 0x03 },
                                           { 0xA2, 0xA3 } });
    patchOrder.patches.push_back({ 0x1000, { 0x00, 0x01, 0x02, 0x03 },
                                           { 0xB0, 0xB1, 0xB2, 0xB3 } });
    ProjectState patchOrderRt;
    CHECK(DeserializeProject(SerializeProject(patchOrder), patchOrderRt));
    CHECK(patchOrderRt.patches.size() == 2);
    CHECK(patchOrderRt.patches[0].address == 0x1002);
    CHECK(patchOrderRt.patches[1].address == 0x1000);
    std::array<uint8_t, 4> patchedImage{};
    for (const auto& patch : patchOrderRt.patches) {
        for (size_t i = 0; i < patch.bytes.size(); ++i) {
            const uint64_t address = patch.address + i;
            if (address >= 0x1000 && address < 0x1000 + patchedImage.size())
                patchedImage[static_cast<size_t>(address - 0x1000)] = patch.bytes[i];
        }
    }
    CHECK((patchedImage == std::array<uint8_t, 4>{ 0xB0, 0xB1, 0xB2, 0xB3 }));

    // Persistence coalesces forward-adjacent byte edits so a normal long Hex
    // editing session cannot exceed the 4096-record reader cap.  This is a
    // representation-only change: addresses, pristine bytes, and patched bytes
    // remain exact.
    ProjectState adjacentEdits;
    adjacentEdits.hash = 0xB17E5;
    for (uint64_t i = 0; i < 5000; ++i)
        adjacentEdits.patches.push_back({ 0x2000 + i, { 0x00 },
                                         { static_cast<uint8_t>(i) } });
    ProjectState adjacentRt;
    CHECK(DeserializeProject(SerializeProject(adjacentEdits), adjacentRt));
    CHECK(adjacentRt.patches.size() == 1);
    CHECK(adjacentRt.patches[0].address == 0x2000 &&
          adjacentRt.patches[0].orig.size() == 5000 &&
          adjacentRt.patches[0].bytes.size() == 5000 &&
          adjacentRt.patches[0].bytes[4999] == static_cast<uint8_t>(4999));

    // A byte span which is legal at the patch-schema level can exceed the JSON
    // parser's token limit after spaced-hex expansion.  The writer splits it
    // into lossless adjacent records which each fit that same reader budget.
    ProjectState largePatch;
    largePatch.hash = 0xB16B00B5;
    PjPatch large;
    large.address = 0x400000;
    large.orig.assign(400000, 0x11);
    large.bytes.assign(400000, 0xCC);
    largePatch.patches.push_back(std::move(large));
    ProjectState largePatchRt;
    CHECK(DeserializeProject(SerializeProject(largePatch), largePatchRt));
    CHECK(largePatchRt.patches.size() == 2);
    CHECK(largePatchRt.patches[0].address == 0x400000 &&
          largePatchRt.patches[1].address ==
              0x400000 + largePatchRt.patches[0].bytes.size());
    CHECK(largePatchRt.patches[0].bytes.size() +
          largePatchRt.patches[1].bytes.size() == 400000);
    CHECK(largePatchRt.patches[0].orig.front() == 0x11 &&
          largePatchRt.patches[1].bytes.back() == 0xCC);
    CHECK(rt.watches.size() == 2 && rt.watches[0] == "rax" && rt.watches[1] == "[rsp+8]");
    CHECK(rt.labels.size() == 1 && rt.labels[0].targetKind == "java_method"
          && rt.labels[0].label == "check_password");
    CHECK(rt.listingLayoutSaved && rt.peHeaderVisible && !rt.peHeaderFolded);
    CHECK(rt.listingSections.size() == 2
          && rt.listingSections[0].rva == 0x1000 && rt.listingSections[0].name == ".text"
          && rt.listingSections[0].visible && !rt.listingSections[0].folded
          && rt.listingSections[1].rva == 0x3000 && rt.listingSections[1].name == ".rsrc"
          && rt.listingSections[1].visible && rt.listingSections[1].folded);
    CHECK(rt.connection.enabled && rt.connection.authEnabled
          && rt.connection.localhostOnly && rt.connection.accessToken == "tok");
    CHECK(rt.connectionEvents.size() == 1 && rt.connectionEvents[0].type == "event"
          && rt.connectionEvents[0].address == "0x1400002000"
          && rt.connectionEvents[0].payloadJson.find("\"tid\"") != std::string::npos);

    // watches alone count as content (so a watch-only project still saves).
    ProjectState w; w.hash = 2; w.watches.push_back("rcx");
    CHECK(w.hasContent());
    ProjectState ev; ev.hash = 3; ev.connectionEvents.push_back({ "event", "tool" });
    CHECK(ev.hasContent());
    ProjectState zeroCursor; zeroCursor.hash = 4;
    zeroCursor.lastCursor = 0; zeroCursor.lastCursorValid = true;
    CHECK(zeroCursor.hasContent());
    ProjectState zeroCursorRt;
    CHECK(DeserializeProject(SerializeProject(zeroCursor), zeroCursorRt));
    CHECK(zeroCursorRt.lastCursorValid && zeroCursorRt.lastCursor == 0);
    ProjectState layoutOnly; layoutOnly.hash = 5; layoutOnly.listingLayoutSaved = true;
    CHECK(layoutOnly.hasContent());
    ProjectState rawOnly; rawOnly.hash = 6; rawOnly.rawMappingSaved = true;
    rawOnly.rawImageBase = 0; rawOnly.rawEntry = 0; rawOnly.rawEntryExplicit = true;
    CHECK(rawOnly.hasContent());
    ProjectState patchSetOnly; patchSetOnly.hash = 7;
    patchSetOnly.patchSets.push_back({ 1, "Baseline", false });
    CHECK(patchSetOnly.hasContent());

    // Legacy version-1 sidecars have no rawMapping object and remain readable;
    // they simply retain the historical fallback mapping behavior.
    ProjectState legacy;
    CHECK(DeserializeProject("{\"version\":1,\"hash\":\"0x1\",\"arch\":\"Thumb\",\"engine\":\"Capstone\"}", legacy));
    CHECK(!legacy.rawMappingSaved && legacy.rawImageBase == 0 && !legacy.rawEntryExplicit &&
          !legacy.rawBigEndian && legacy.rawRiscvCompressed &&
          legacy.rawDecoderFeatureBits == kDecoderFeatureRiscvCompressed);
    CHECK(legacy.functionOverrides.empty() && legacy.dataOverrides.empty());
    ProjectState legacyV2;
    CHECK(DeserializeProject("{\"version\":2,\"hash\":\"0x2\",\"lastCursor\":\"0x0\",\"lastCursorValid\":true}", legacyV2));
    CHECK(legacyV2.lastCursorValid && legacyV2.lastCursor == 0 &&
          legacyV2.functionOverrides.empty() && legacyV2.dataOverrides.empty() &&
          !legacyV2.rawBigEndian && legacyV2.rawRiscvCompressed &&
          legacyV2.rawDecoderFeatureBits == kDecoderFeatureRiscvCompressed);

    ProjectState legacyRawOptions;
    CHECK(DeserializeProject("{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\"}}",
                             legacyRawOptions));
    CHECK(legacyRawOptions.rawMappingSaved && !legacyRawOptions.rawBigEndian &&
          legacyRawOptions.rawRiscvCompressed &&
          legacyRawOptions.rawDecoderFeatureBits == kDecoderFeatureRiscvCompressed);

    ProjectState legacyRvcOff;
    CHECK(DeserializeProject(
        "{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\",\"riscvCompressed\":false}}",
        legacyRvcOff));
    CHECK(!legacyRvcOff.rawRiscvCompressed &&
          legacyRvcOff.rawDecoderFeatureBits == 0);

    ProjectState featureBitsOnly;
    CHECK(DeserializeProject(
        "{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\",\"featureBits\":14}}",
        featureBitsOnly));
    CHECK(!featureBitsOnly.rawRiscvCompressed &&
          featureBitsOnly.rawDecoderFeatureBits == 14);

    // Version 3 override records are authoritative, so malformed or ambiguous
    // inputs reject the sidecar instead of being silently reinterpreted.
    ProjectState rejected;
    ProjectState sparseV4;
    CHECK(DeserializeProject("{\"version\":4}", sparseV4));
    CHECK(sparseV4.patchSets.empty() && sparseV4.patches.empty());
    CHECK(!DeserializeProject("{\"version\":6}", rejected));
    CHECK(!DeserializeProject("{\"version\":3.5}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"functionOverrides\":[{\"a\":\"0x0\",\"action\":\"define\",\"size\":\"0x0\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"functionOverrides\":[{\"a\":\"0xFFFFFFFFFFFFFFFF\",\"action\":\"define\",\"size\":\"0x2\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"functionOverrides\":[{\"a\":\"0x10\",\"action\":\"define\"},{\"a\":\"0x10\",\"action\":\"undefine\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"functionOverrides\":[{\"a\":\"0x10\",\"action\":\"undefine\",\"noreturn\":true}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"functionOverrides\":[{\"a\":\"0x10\",\"action\":\"define\",\"mode\":\"aarch64\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"dataOverrides\":[{\"a\":\"0x0\",\"size\":\"0x20\",\"kind\":\"data\"},{\"a\":\"0x10\",\"size\":\"0x20\",\"kind\":\"code\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"dataOverrides\":[{\"a\":\"0x0\",\"size\":\"0x0\",\"kind\":\"string\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"dataOverrides\":[{\"a\":\"0xFFFFFFFFFFFFFFFF\",\"size\":\"0x2\",\"kind\":\"data\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\",\"featureBits\":16}}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\",\"featureBits\":1,\"riscvCompressed\":false}}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\",\"featureBits\":0,\"riscvCompressed\":true}}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\",\"featureBits\":\"1\"}}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\",\"featureBits\":1.5}}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\",\"featureBits\":-1}}", rejected));
    std::string tooMany = "{\"version\":3,\"functionOverrides\":[";
    for (size_t i = 0; i < 65537; ++i) { if (i) tooMany += ','; tooMany += "{}"; }
    tooMany += "]}";
    CHECK(!DeserializeProject(tooMany, rejected));

    // Raw mapping strings define the coordinate system for every saved VA.
    // Malformed, trailing-junk, overflowing, or non-string values must reject
    // the sidecar instead of silently becoming a valid base/entry at VA 0.
    auto replaceOnce = [](std::string source, const std::string& from,
                          const std::string& to) {
        const size_t at = source.find(from);
        if (at != std::string::npos) source.replace(at, from.size(), to);
        return source;
    };
    const std::string rawJson = SerializeProject(st);
    CHECK(!DeserializeProject(replaceOnce(rawJson, "\"base\": \"0x0\"",
                                                   "\"base\": \"garbage\""), rejected));
    CHECK(!DeserializeProject(replaceOnce(rawJson, "\"entry\": \"0x0\"",
                                                   "\"entry\": \"0x0junk\""), rejected));
    CHECK(!DeserializeProject(replaceOnce(rawJson, "\"base\": \"0x0\"",
                                                   "\"base\": \"0x10000000000000000\""), rejected));
    CHECK(!DeserializeProject(replaceOnce(rawJson, "\"address\": \"0x0\"",
                                                   "\"address\": 0"), rejected));

    // The raw-landmark schema bound applies to the input collection before
    // deduplication.  Exactly the bounded number of duplicate records remains
    // compatible and collapses to one landmark, but one more record rejects
    // the complete sidecar instead of spending unbounded time deduplicating it.
    auto duplicateLandmarkProject = [](size_t count) {
        std::string text =
            "{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"entry\":\"0x0\",\"landmarks\":[";
        for (size_t i = 0; i < count; ++i) {
            if (i) text += ',';
            text += "{\"address\":\"0x10\",\"name\":\"reset\",\"evidence\":\"fixture\"}";
        }
        text += "]}}";
        return text;
    };
    ProjectState boundedLandmarks;
    CHECK(DeserializeProject(duplicateLandmarkProject(4096), boundedLandmarks));
    CHECK(boundedLandmarks.rawLandmarks.size() == 1 &&
          boundedLandmarks.rawLandmarks[0].address == 0x10);
    CHECK(!DeserializeProject(duplicateLandmarkProject(4097), rejected));

    // Every persisted address and every patch byte string is authoritative.
    // Malformed text rejects the complete sidecar; it must never collapse to VA
    // zero or retain a valid-looking hex prefix.
    CHECK(!DeserializeProject("{\"version\":3,\"names\":[{\"a\":\"garbage\",\"v\":\"x\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"bookmarks\":[{\"a\":\"0x10junk\",\"label\":\"x\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"breakpoints\":[{\"a\":1}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"patches\":[{\"a\":\"garbage\",\"orig\":\"90\",\"bytes\":\"CC\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"patches\":[{\"a\":\"0x10\",\"orig\":\"90 ZZ\",\"bytes\":\"CC DD\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"patches\":[{\"a\":\"0x10\",\"orig\":\"9\",\"bytes\":\"C\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"patches\":[{\"a\":\"0xFFFFFFFFFFFFFFFF\",\"orig\":\"90\",\"bytes\":\"CC\"}]}", rejected));
    ProjectState zeroPatch;
    CHECK(DeserializeProject("{\"version\":3,\"patches\":[{\"a\":\"0x0\",\"orig\":\"90\",\"bytes\":\"CC\"}]}", zeroPatch));
    CHECK(zeroPatch.patches.size() == 1 && zeroPatch.patches[0].address == 0 &&
          zeroPatch.patches[0].patchSetId == kUngroupedPatchSetId &&
          zeroPatch.patchSets.empty());

    // Version 4 set membership is exact. Alternative experiments may overlap
    // only while at most one conflicting set is enabled; malformed identities,
    // ambiguous names, and orphaned patch membership reject the whole sidecar.
    const char* alternatives =
        "{\"version\":4,\"patchSets\":["
        "{\"id\":\"0x1\",\"name\":\"Force true\",\"enabled\":true},"
        "{\"id\":\"0x2\",\"name\":\"Force false\",\"enabled\":false}],"
        "\"patches\":["
        "{\"a\":\"0x10\",\"orig\":\"31 C0\",\"bytes\":\"B0 01\",\"set\":\"0x1\"},"
        "{\"a\":\"0x10\",\"orig\":\"31 C0\",\"bytes\":\"30 C0\",\"set\":\"0x2\"}]}";
    ProjectState alternativesRt;
    CHECK(DeserializeProject(alternatives, alternativesRt));
    CHECK(alternativesRt.patchSets.size() == 2 &&
          alternativesRt.patches.size() == 2 &&
          alternativesRt.patches[1].patchSetId == 2);
    CHECK(!DeserializeProject(
        "{\"version\":4,\"patchSets\":[{\"id\":\"0x0\",\"name\":\"bad\"}]}",
        rejected));
    CHECK(!DeserializeProject(
        "{\"version\":4,\"patchSets\":[{\"id\":\"0x1\",\"name\":\"A\"},{\"id\":\"0x1\",\"name\":\"B\"}]}",
        rejected));
    CHECK(!DeserializeProject(
        "{\"version\":4,\"patchSets\":[{\"id\":\"0x1\",\"name\":\"Gate\"},{\"id\":\"0x2\",\"name\":\"gate\"}]}",
        rejected));
    CHECK(!DeserializeProject(
        "{\"version\":4,\"patches\":[{\"a\":\"0x10\",\"orig\":\"90\",\"bytes\":\"CC\",\"set\":\"0x9\"}]}",
        rejected));
    CHECK(!DeserializeProject(
        "{\"version\":4,\"patches\":[{\"a\":\"0x10\",\"orig\":\"90\",\"bytes\":\"CC\"}]}",
        rejected));

    // Missing fields remain compatible with v1-v3, but a present known field
    // with the wrong JSON type invalidates the complete candidate.
    ProjectState sparse;
    CHECK(DeserializeProject("{\"version\":1}", sparse));
    CHECK(!DeserializeProject("{\"version\":3,\"lastCursorValid\":\"yes\"}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"listingLayout\":{\"peHeaderVisible\":1}}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"listingLayout\":{\"sections\":[{\"rva\":\"0x0\",\"name\":\"x\",\"visible\":\"yes\"}]}}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"labels\":[{\"kind\":\"method\",\"target\":\"x\",\"label\":\"y\",\"confidence\":\"high\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"connection\":{\"enabled\":\"yes\"}}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"connection\":{\"accessToken\":7}}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"syntheses\":[{\"a\":\"0x0\",\"z3\":\"yes\"}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"connectionEvents\":[{\"type\":\"event\",\"source\":\"tool\",\"address\":16,\"payload\":{}}]}", rejected));
    CHECK(!DeserializeProject("{\"version\":3,\"connectionEvents\":[{\"type\":\"event\",\"source\":\"tool\",\"address\":\"0x10000000000000000\",\"payload\":{}}]}", rejected));

    std::string tooManyWatches = "{\"version\":3,\"watches\":[";
    for (size_t i = 0; i < 4097; ++i) {
        if (i) tooManyWatches += ',';
        tooManyWatches += "{\"v\":\"x\"}";
    }
    tooManyWatches += "]}";
    CHECK(!DeserializeProject(tooManyWatches, rejected));

    // Parser budgets are enforced before publishing a partial tree, and a
    // failed parse leaves the caller's prior Value untouched.
    json::Value preserved = json::Value::Str("unchanged");
    json::JsonParseLimits limits;
    limits.maxNodes = 3;
    CHECK(!json::Parse("[null,null,null]", preserved, limits));
    CHECK(preserved.isStr() && preserved.str == "unchanged");
    limits = {};
    limits.maxDepth = 2;
    CHECK(json::Parse("[[0]]", preserved, limits));
    CHECK(!json::Parse("[[[0]]]", preserved, limits));
    limits = {};
    limits.maxStringBytes = 3;
    CHECK(!json::Parse("\"four\"", preserved, limits));
    CHECK(!json::Parse("[\"aa\",\"bb\"]", preserved, limits));
    limits = {};
    limits.maxStringTokenBytes = 3;
    CHECK(json::Parse("\"abc\"", preserved, limits));
    CHECK(preserved.isStr() && preserved.str == "abc");
    CHECK(!json::Parse("\"four\"", preserved, limits));
    CHECK(preserved.isStr() && preserved.str == "abc");
    limits = {};
    limits.maxContainerEntries = 2;
    CHECK(!json::Parse("[1,2,3]", preserved, limits));
    limits = {};
    limits.maxNumberTokenBytes = 3;
    CHECK(!json::Parse("1234", preserved, limits));
    limits = {};
    for (const char* malformed : { "+1", ".5", "01", "1.", "1e", "1e+" })
        CHECK(!json::Parse(malformed, preserved, limits));
    CHECK(json::Parse("-0.5e+2", preserved, limits));

    // Duplicate object members are ambiguous and therefore malformed at every
    // depth.  Comparison uses decoded keys, so an escaped spelling cannot
    // evade the check.  As with every parse failure, the caller's Value is not
    // partially replaced.
    preserved = json::Value::Str("duplicate-sentinel");
    CHECK(!json::Parse("{\"version\":1,\"version\":3}", preserved, limits));
    CHECK(preserved.isStr() && preserved.str == "duplicate-sentinel");
    CHECK(!json::Parse("{\"outer\":{\"a\":1,\"\\u0061\":2}}", preserved, limits));
    CHECK(preserved.isStr() && preserved.str == "duplicate-sentinel");
    CHECK(!DeserializeProject("{\"version\":1,\"version\":3}", rejected));
    CHECK(!DeserializeProject(
        "{\"version\":3,\"rawMapping\":{\"base\":\"0x0\",\"base\":\"0x1\",\"entry\":\"0x0\"}}",
        rejected));

    // hasContent() gates the empty-project save guard.
    ProjectState empty; empty.hash = 1; empty.arch = "x64"; empty.engine = "Zydis";
    CHECK(!empty.hasContent());        // metadata alone is not "content"
    empty.comments[0x10] = "x";
    CHECK(empty.hasContent());

    // Filesystem persistence is recoverable and reports commit failures. A
    // second successful save creates last-known-good backups for both files;
    // corrupting their primaries must transparently recover the first version.
    std::error_code fsError;
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path persistenceRoot = fs::temp_directory_path() /
        ("disasmstudio_project_test_" + std::to_string(nonce));
    fs::remove_all(persistenceRoot, fsError);
    fsError.clear();
    fs::create_directories(persistenceRoot, fsError);
    CHECK(!fsError);
    {
        ScopedProjectsDir projectsDir;
        CHECK(projectsDir.set(persistenceRoot));

        // Exercise the real atomic save/load path for the JSON-token boundary,
        // not only the pure serializer.  The persisted representation is split,
        // while the exact ordered bytes remain reconstructible on reopen.
        const fs::path patchBoundaryRoot = persistenceRoot / "patch-boundary";
        fsError.clear();
        fs::create_directories(patchBoundaryRoot, fsError);
        CHECK(!fsError && projectsDir.set(patchBoundaryRoot));
        // Clearing the last annotation is still an authoritative save. It must
        // replace an older sidecar instead of reporting success and reviving
        // the removed state the next time this binary opens.
        ProjectState cleared;
        cleared.hash = 0xC1EA1234;
        cleared.name = "cleared-state";
        const fs::path clearedPath = ProjectPathForHash(cleared.hash);
        const ProjectSaveResult freshEmptySave = SaveProjectDetailed(cleared);
        CHECK(freshEmptySave.saved && !freshEmptySave.sidecarWritten);
        CHECK(!fs::exists(clearedPath));
        cleared.notes = "the last annotation";
        CHECK(SaveProject(cleared));
        cleared.notes.clear();
        CHECK(!cleared.hasContent());
        const ProjectSaveResult clearedSave = SaveProjectDetailed(cleared);
        CHECK(clearedSave.saved && clearedSave.sidecarWritten);
        ProjectState clearedReloaded;
        CHECK(LoadProject(cleared.hash, clearedReloaded));
        CHECK(!clearedReloaded.hasContent());

        // The same rule applies after recovery from a backup-only project.
        // Its absent primary must not make deletion look like a fresh project.
        CHECK(fs::remove(clearedPath));
        CHECK(LoadProject(cleared.hash, clearedReloaded));
        CHECK(clearedReloaded.notes == "the last annotation");
        const ProjectSaveResult clearedBackupSave = SaveProjectDetailed(cleared);
        CHECK(clearedBackupSave.saved && clearedBackupSave.sidecarWritten);
        CHECK(LoadProject(cleared.hash, clearedReloaded));
        CHECK(!clearedReloaded.hasContent());

        const ProjectSaveResult completeStateSave = SaveProjectDetailed(st);
        CHECK(completeStateSave.saved && completeStateSave.sidecarWritten &&
              completeStateSave.recentsUpdated && completeStateSave.error.empty());
        ProjectState completeStateReloaded;
        CHECK(LoadProject(st.hash, completeStateReloaded));
        CHECK(completeStateReloaded.connectionEvents.size() == 1 &&
              completeStateReloaded.rawDecoderFeatureBits == st.rawDecoderFeatureBits);
        const ProjectSaveResult largePatchSave = SaveProjectDetailed(largePatch);
        CHECK(largePatchSave.saved && largePatchSave.sidecarWritten &&
              largePatchSave.recentsUpdated && largePatchSave.error.empty());
        ProjectState largePatchReloaded;
        CHECK(LoadProject(largePatch.hash, largePatchReloaded));
        CHECK(largePatchReloaded.patches.size() == 2 &&
              largePatchReloaded.patches[0].bytes.size() +
                  largePatchReloaded.patches[1].bytes.size() == 400000);
        CHECK(projectsDir.set(persistenceRoot));

        ProjectState untouched;
        untouched.name = "sentinel";
        const ProjectLoadResult absent = LoadProjectDetailed(0xAB5E17, untouched);
        CHECK(!absent.loaded && absent.primary == ProjectLoadAttempt::Missing &&
              absent.backup == ProjectLoadAttempt::Missing);
        CHECK(!ProjectLoadAttemptRequiresWarning(absent.primary) &&
              !ProjectLoadAttemptRequiresWarning(absent.backup));
        CHECK(untouched.name == "sentinel");

        // An existing candidate which cannot be read as a bounded regular file
        // is different from an absent project and must reach the UI as a warning.
        const uint64_t unreadableHash = 0xAB5E18;
        fsError.clear();
        fs::create_directory(ProjectPathForHash(unreadableHash), fsError);
        CHECK(!fsError);
        ProjectState rejected;
        const ProjectLoadResult unavailable = LoadProjectDetailed(unreadableHash, rejected);
        CHECK(!unavailable.loaded &&
              unavailable.primary == ProjectLoadAttempt::Unavailable &&
              unavailable.backup == ProjectLoadAttempt::Missing);
        CHECK(ProjectLoadAttemptRequiresWarning(unavailable.primary));

        ProjectState first;
        first.hash = 0xFACE1234;
        first.binaryPath = "C:/fixtures/recover.exe";
        first.arch = "x64";
        first.engine = "Zydis";
        first.name = "first-version";
        first.lastOpenedUnix = 100;
        first.notes = "known-good project";
        CHECK(SaveProject(first));

        ProjectState second = first;
        second.name = "second-version";
        second.lastOpenedUnix = 200;
        second.notes = "new primary project";
        CHECK(SaveProject(second));

        const fs::path projectPath = ProjectPathForHash(first.hash);
        fs::path projectBackup = projectPath;
        projectBackup += ".bak";
        CHECK(fs::exists(projectPath));
        CHECK(fs::exists(projectBackup));
        {
            std::ofstream corrupt(projectPath, std::ios::binary | std::ios::trunc);
            corrupt << "{";
            corrupt.flush();
            CHECK(static_cast<bool>(corrupt));
        }
        ProjectState recovered;
        const ProjectLoadResult malformedRecovery = LoadProjectDetailed(first.hash, recovered);
        CHECK(malformedRecovery.loaded && malformedRecovery.recoveredFromBackup());
        CHECK(malformedRecovery.primary == ProjectLoadAttempt::Malformed &&
              malformedRecovery.backup == ProjectLoadAttempt::Loaded &&
              !malformedRecovery.error.empty());
        CHECK(recovered.name == first.name);
        CHECK(recovered.notes == first.notes);

        // A duplicate in a nested object is syntactically complete JSON but
        // remains a malformed authoritative sidecar.  It must take the same
        // last-known-good backup path as truncated JSON.
        {
            std::ofstream ambiguous(projectPath, std::ios::binary | std::ios::trunc);
            ambiguous <<
                "{\"version\":3,\"hash\":\"0xFACE1234\",\"rawMapping\":{"
                "\"base\":\"0x0\",\"base\":\"0x1\",\"entry\":\"0x0\"}}";
            ambiguous.flush();
            CHECK(static_cast<bool>(ambiguous));
        }
        recovered.reset();
        const ProjectLoadResult duplicateRecovery = LoadProjectDetailed(first.hash, recovered);
        CHECK(duplicateRecovery.loaded && duplicateRecovery.recoveredFromBackup());
        CHECK(duplicateRecovery.primary == ProjectLoadAttempt::Malformed &&
              duplicateRecovery.backup == ProjectLoadAttempt::Loaded);
        CHECK(recovered.name == first.name && recovered.notes == first.notes);

        // A syntactically valid primary for a different hash is still corrupt
        // for this path; select the matching backup and do not publish it.
        ProjectState wrongIdentity = second;
        wrongIdentity.hash = 0x99999999;
        {
            std::ofstream wrong(projectPath, std::ios::binary | std::ios::trunc);
            const std::string json = SerializeProject(wrongIdentity);
            wrong.write(json.data(), static_cast<std::streamsize>(json.size()));
        }
        recovered.reset();
        const ProjectLoadResult identityRecovery = LoadProjectDetailed(first.hash, recovered);
        CHECK(identityRecovery.loaded && identityRecovery.recoveredFromBackup());
        CHECK(identityRecovery.primary == ProjectLoadAttempt::IdentityMismatch &&
              identityRecovery.backup == ProjectLoadAttempt::Loaded);
        CHECK(recovered.hash == first.hash && recovered.name == first.name);

        const fs::path recentsPath = persistenceRoot / "index.json";
        fs::path recentsBackup = recentsPath;
        recentsBackup += ".bak";
        CHECK(fs::exists(recentsPath));
        CHECK(fs::exists(recentsBackup));
        {
            std::ofstream corrupt(recentsPath, std::ios::binary | std::ios::trunc);
            corrupt << "not json";
            corrupt.flush();
            CHECK(static_cast<bool>(corrupt));
        }
        const auto recoveredRecents = LoadRecents();
        CHECK(recoveredRecents.size() == 1);
        CHECK(recoveredRecents[0].hash == first.hash);
        CHECK(recoveredRecents[0].name == first.name);
        CHECK(recoveredRecents[0].lastOpenedUnix == first.lastOpenedUnix);

        // Directories at the final filenames force replacement failures after
        // the sibling temp was written.  A sidecar failure is authoritative;
        // recents failure is only a warning and must not leave a document dirty.
        const fs::path failureRoot = persistenceRoot / "failures";
        fsError.clear();
        fs::create_directories(failureRoot, fsError);
        CHECK(!fsError);
        CHECK(projectsDir.set(failureRoot));
        ProjectState failedSidecar = first;
        failedSidecar.hash = 0xBAD00001;
        fsError.clear();
        fs::create_directory(ProjectPathForHash(failedSidecar.hash), fsError);
        CHECK(!fsError);
        const ProjectSaveResult sidecarFailure = SaveProjectDetailed(failedSidecar);
        CHECK(!sidecarFailure.saved && !sidecarFailure.sidecarWritten &&
              !sidecarFailure.error.empty());

        ProjectState failedRecents;
        failedRecents.hash = 0xBAD00002;
        failedRecents.name = "recents-only";
        CHECK(!failedRecents.hasContent());
        fsError.clear();
        fs::copy_file(recentsBackup, failureRoot / "index.json.bak",
                      fs::copy_options::overwrite_existing, fsError);
        CHECK(!fsError);
        fsError.clear();
        fs::create_directory(failureRoot / "index.json", fsError);
        CHECK(!fsError);
        const ProjectSaveResult recentsFailure = SaveProjectDetailed(failedRecents);
        CHECK(recentsFailure.saved && !recentsFailure.sidecarWritten &&
              recentsFailure.recentsAttempted && !recentsFailure.recentsUpdated &&
              recentsFailure.error.empty() && !recentsFailure.warning.empty());
        CHECK(SaveProject(failedRecents)); // compatibility API reports authoritative success

        // Writer-side schema limits are enforced before atomic replacement by
        // round-tripping through the same bounded reader.
        ProjectState oversizedName = first;
        oversizedName.hash = 0xBAD00003;
        oversizedName.name.assign(4097, 'n');
        const ProjectSaveResult invalidState = SaveProjectDetailed(oversizedName);
        CHECK(!invalidState.saved && !invalidState.error.empty());
        CHECK(!fs::exists(ProjectPathForHash(oversizedName.hash)));

        ProjectState tooManyNonAdjacent;
        tooManyNonAdjacent.hash = 0xBAD00004;
        for (uint64_t i = 0; i < 4097; ++i)
            tooManyNonAdjacent.patches.push_back(
                { 0x100000 + i * 2, { 0x00 }, { 0x90 } });
        const ProjectSaveResult tooManyResult =
            SaveProjectDetailed(tooManyNonAdjacent);
        CHECK(!tooManyResult.saved && !tooManyResult.error.empty());
        CHECK(!fs::exists(ProjectPathForHash(tooManyNonAdjacent.hash)));
        CHECK(!RemoveRecent(first.hash));
        for (const auto& entry : fs::directory_iterator(failureRoot))
            CHECK(entry.path().filename().string().find(".tmp.") == std::string::npos);
    }
    fsError.clear();
    fs::remove_all(persistenceRoot, fsError);
    CHECK(!fsError);

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("project_roundtrip_test: all checks passed\n");
    return 0;
}
