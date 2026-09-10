// Decode real x86/x64 bytes through the production backend, then check naming
// and the source-valid notes consumed by Binary View's inline annotation cache.
#include "Core/BinaryFile.h"
#include "Core/CFG.h"
#include "Core/FuncAnnotate.h"
#include "Core/FunctionNamer.h"
#include "Disasm/CapstoneDisassembler.h"
#include "Disasm/ZydisDisassembler.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;
static int failures = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL line %d: %s\n", __LINE__, #condition); ++failures; } } while (0)

static const FnNote* noteAt(const FuncAnnotations& annotations, uint64_t va, NoteKind kind) {
    for (const auto& note : annotations.notes)
        if (note.sourceValid && note.va == va && note.kind == kind) return &note;
    return nullptr;
}

static void checkMachineCode(Arch arch, IDisassembler& decoder) {
    struct Sample { std::vector<uint8_t> bytes; const char* name; };
    const std::vector<Sample> samples = {
        {{0x8B,0x41,0x1C,0xC3}, "read_field_1c"},
        {{0x83,0x79,0x1C,0x01,0x0F,0x94,0xC0,0x0F,0xB6,0xC0,0xC3}, "is_field_1c_one"},
        {{0xC7,0x41,0x1C,0x01,0x00,0x00,0x00,0xC3}, "write_field_1c_one"},
        {{0xC7,0x41,0x1C,0x00,0x00,0x00,0x00,0xC3}, "write_field_1c_zero"},
        // Full-width field comparison, then two reachable Boolean returns.
        {{0x83,0x79,0x1C,0x01,0x75,0x06,0xB8,0x01,0x00,0x00,0x00,0xC3,0x31,0xC0,0xC3}, "is_field_1c_one"},
        // A byte load is checked as a full-width zero-extended value.
        {{0x0F,0xB6,0x41,0x1C,0x85,0xC0,0x74,0x06,0xB8,0x01,0x00,0x00,0x00,0xC3,0x31,0xC0,0xC3}, nullptr},
        // The loaded field is overwritten before the check: no field predicate.
        {{0x8B,0x41,0x1C,0x31,0xC0,0x85,0xC0,0x0F,0x95,0xC0,0x0F,0xB6,0xC0,0xC3}, nullptr},
        // Only AL is defined at RET, so do not claim a full-width Boolean return.
        {{0x83,0x79,0x1C,0x01,0x0F,0x94,0xC0,0xC3}, nullptr},
        // MOV preserves the old comparison's flags while overwriting ECX.
        {{0x83,0xF9,0x01,0xB9,0x00,0x00,0x00,0x00,0x75,0x06,0xB8,0x01,0x00,0x00,0x00,0xC3,0x31,0xC0,0xC3}, nullptr},
        {{0x83,0xF9,0x01,0xB9,0x00,0x00,0x00,0x00,0x0F,0x94,0xC0,0xC3}, nullptr},
    };
    CHECK(decoder.ready());
    const char* path = arch == Arch::X64 ? "ds_state_pipeline_x64.bin" : "ds_state_pipeline_x86.bin";
    for (size_t i = 0; i < samples.size(); ++i) {
        const auto& sample = samples[i];
        { std::ofstream file(path, std::ios::binary | std::ios::trunc);
          file.write(reinterpret_cast<const char*>(sample.bytes.data()), sample.bytes.size());
          CHECK(file.good()); }
        BinaryFile binary;
        CHECK(binary.loadRaw(path, 0)); // VA zero is a real instruction location.
        FunctionNamer namer;
        const auto names = namer.name(binary, decoder,
            {{0, static_cast<uint32_t>(sample.bytes.size()), false, "sub_0"}},
            0, false, false, {}, {});
        CHECK(names.size() == 1);
        if (names.size() != 1) continue;
        if (sample.name) {
            if (names[0].name != sample.name)
                std::printf("sample %zu (%s): got %s, expected %s\n", i,
                    arch == Arch::X64 ? "x64" : "x86", names[0].name.c_str(), sample.name);
            CHECK(names[0].guessed && names[0].name == sample.name);
            CHECK(!names[0].reason.empty());
        }
        if (i == 6 || i == 7) CHECK(names[0].name.find("is_field_") == std::string::npos);
        CHECK(names[0].name.find("zen") == std::string::npos);

        const auto graph = BuildCFG(sample.bytes.data(), sample.bytes.size(), 0, decoder);
        CHECK(graph.complete);
        AnnotateOptions options;
        options.x64 = arch == Arch::X64;
        const auto annotations = AnnotateFunction(graph, options);
        for (const auto& note : annotations.notes) {
            CHECK(!note.text.empty() && !note.evidence.empty());
            CHECK(note.text.find("Zen") == std::string::npos);
        }
        if (i >= 1 && i <= 4) {
            const auto* state = noteAt(annotations, 0, NoteKind::State);
            CHECK(state);
            if (state) {
                CHECK(state->text.find("0x1c") != std::string::npos ||
                      state->text.find("0x1C") != std::string::npos);
                CHECK(state->confidence > 0.0f && state->confidence <= 1.0f);
                std::printf("%s: %s\n", names[0].name.c_str(), state->text.c_str());
            }
        }
        if (i == 4) {
            const auto* branch = noteAt(annotations, 4, NoteKind::Branch);
            CHECK(branch);
            if (branch) {
                CHECK(branch->text.find("is not 1") != std::string::npos);
                CHECK(branch->text.find("falls through") != std::string::npos);
                std::printf("branch: %s\n", branch->text.c_str());
            }
        }
        if (i == 5) {
            const auto* state = noteAt(annotations, 4, NoteKind::State);
            CHECK(state);
            if (state) {
                CHECK(state->text.find("nonzero") != std::string::npos);
                CHECK(state->text.find("0x1c") != std::string::npos ||
                      state->text.find("0x1C") != std::string::npos);
                std::printf("loaded field: %s\n", state->text.c_str());
            }
        }
        if (i == 8 || i == 9) {
            const auto* consumer = noteAt(annotations, 8, i == 8 ? NoteKind::Branch : NoteKind::State);
            CHECK(consumer);
            if (consumer) {
                CHECK(consumer->text.find("value checked at 0x0") != std::string::npos);
                std::printf("earlier comparison: %s\n", consumer->text.c_str());
            }
        }
    }
    std::remove(path);
}

int main() {
    for (Arch arch : {Arch::X64, Arch::X86}) {
        ZydisDisassembler zydis(arch);
        CapstoneDisassembler capstone(arch);
        std::printf("Zydis %s\n", arch == Arch::X64 ? "x64" : "x86");
        checkMachineCode(arch, zydis);
        std::printf("Capstone %s\n", arch == Arch::X64 ? "x64" : "x86");
        checkMachineCode(arch, capstone);
    }
    std::printf("state_semantics_pipeline_test: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
