#include "Core/BinaryFile.h"
#include "Core/FunctionAnalyzer.h"
#include "Core/GameMakerArchive.h"
#include "Core/CodeDataClassifier.h"
#include "Disasm/GmlDisassembler.h"
#include "gamemaker_fixture.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>

using namespace ds;
static int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::printf("FAIL %d: %s\n", __LINE__, #expr); ++failures; } } while (0)

int main() {
    const auto fixture = gmltest::BuildArchive();
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto path = std::filesystem::temp_directory_path() /
        ("disasm_gml_load_" + std::to_string(stamp) + ".win");
    auto write = [&](const auto& bytes) {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        stream.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        return bool(stream);
    };
    CHECK(write(fixture.bytes));
    const auto u8 = path.u8string();
    const std::string fileName(reinterpret_cast<const char*>(u8.data()), u8.size());
    BinaryFile binary;
    CHECK(binary.load(fileName));
    CHECK(binary.format() == BinFormat::GameMakerArchive);
    CHECK(binary.machine() == MachineArch::GML);
    CHECK(binary.gameMakerArchive() && binary.gameMakerArchive()->code.size() == 2);
    CHECK(!binary.hasEntryPoint());
    CHECK(binary.imageBase() == 0);
    CHECK(binary.sections().size() == 2); // one physical shared body, one archive backing
    CHECK(binary.sections()[0].executable);
    CHECK(binary.sections()[0].rawOffset == fixture.rootOffset);
    CHECK(binary.sections()[0].rawSize == fixture.rootLength);
    uint64_t offset = UINT64_MAX, va = UINT64_MAX;
    CHECK(binary.vaToOffset(fixture.childOffset, offset) && offset == fixture.childOffset);
    CHECK(binary.offsetToVA(offset, va) && va == fixture.childOffset);
    CHECK(!binary.canWriteImage(fixture.rootOffset, 4));

    DecoderConfig config;
    config.arch = Arch::X64;
    config = DecoderConfigForImage(binary, config);
    CHECK(config.arch == Arch::GML && config.byteOrder == ByteOrder::Little);
    CHECK(ArchInstructionAlignment(config) == 4);
    CHECK(!ArchSupportsDebugger(config.arch) && !ArchSupportsAssembler(config.arch));
    CHECK(!ArchSupportsDecompiler(config.arch));
    GmlDisassembler decoder(config);
    AttachGameMakerArchive(decoder, binary.gameMakerArchive());
    CHECK(decoder.ready());
    FunctionAnalyzer analyzer;
    const auto functions = analyzer.analyze(binary, decoder);
    CHECK(functions.size() == 2);
    if (functions.size() == 2) {
        CHECK(functions[0].address == fixture.rootOffset);
        CHECK(functions[1].address == fixture.childOffset);
        CHECK(functions[1].seedKind == FunctionSeedKind::GameMakerCode);
        CHECK(functions[1].boundaryConfidence == FunctionBoundaryConfidence::Authoritative);
        CHECK(functions[1].size == 8); // push + return, not shared blob tail
        bool rootOwnsChild = false;
        for (const auto& chunk : functions[0].chunks)
            rootOwnsChild |= fixture.childOffset >= chunk.address &&
                fixture.childOffset - chunk.address < chunk.size;
        CHECK(!rootOwnsChild);
    }
    const auto classified = ClassifyCodeData(binary, decoder, config, {}, {});
    CHECK(classified.stats.codeBytes == fixture.rootLength);
    CHECK(classified.stats.dataBytes == 0);

    auto corrupt = fixture.bytes;
    gmltest::Set32(corrupt, fixture.codeRecord + 12, 0x7fffffff);
    CHECK(write(corrupt));
    CHECK(!binary.load(fileName));
    CHECK(binary.loadError() == BinaryLoadError::MalformedGameMakerArchive);
    CHECK(!binary.loaded() && !binary.gameMakerArchive());
    CHECK(write(fixture.bytes));
    BinaryLoadOptions options;
    options.cancelled = [] { return true; };
    CHECK(!binary.load(fileName, options));
    CHECK(binary.loadError() == BinaryLoadError::Cancelled);
    CHECK(binary.load(fileName));
    binary.clear();
    CHECK(!binary.gameMakerArchive());
    std::error_code error;
    std::filesystem::remove(path, error);
    if (!failures) std::puts("gamemaker_load_test: all checks passed");
    return failures ? 1 : 0;
}
