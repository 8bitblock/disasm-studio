// Pure coverage for recursive executable code/data classification. The fake ISA
// keeps decoder behavior deterministic while the image contains realistic native
// pointer tables, an indirect jump table, a referenced string, CET landing pad,
// and linker padding.

#include "Core/CodeDataClassifier.h"
#include "Core/BinaryFile.h"
#include "Disasm/IDisassembler.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(x, msg) do { if (!(x)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

static constexpr uint64_t kBase = 0x100000;

struct FixtureDis final : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "fixture"; }

    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        if (!p || !n) return false;
        out = {}; out.address = va; out.length = 1; out.bytes = "42";
        if (n >= 4 && p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) {
            out.length = 4; out.mnemonic = "endbr64"; out.bytes = "F3 0F 1E FA";
        } else if (p[0] == 0xA0 && n >= 2) {
            out.length = 2; out.mnemonic = "mov";
            out.operands = "rax, [0x100060]";
        } else if (p[0] == 0xB0 && n >= 2) {
            out.length = 2; out.mnemonic = "jmp";
            out.operands = "[rax*8 + 0x1000A0]";
            out.isBranch = true;
        } else if (p[0] == 0xC3) {
            out.mnemonic = "ret"; out.isRet = out.isBranch = true;
        } else {
            out.mnemonic = "nop";
        }
        return true;
    }

    std::vector<Instruction> disassemble(const uint8_t* p, size_t n, uint64_t va,
                                         size_t maxInstructions) override {
        std::vector<Instruction> out;
        size_t off = 0;
        while (off < n && (!maxInstructions || out.size() < maxInstructions)) {
            Instruction in;
            if (!decodeOne(p + off, n - off, va + off, in) || !in.length) break;
            out.push_back(in); off += in.length;
        }
        return out;
    }
};

static void put64(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

static void put64be(std::vector<uint8_t>& bytes, size_t offset, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i)
        bytes[offset + i] = static_cast<uint8_t>(value >> ((7u - i) * 8u));
}

int main() {
    std::vector<uint8_t> bytes(0x200, 0x42); // unclaimed bytes stay explicitly Unknown
    bytes[0x00] = 0xA0; bytes[0x01] = 0x00; // referenced string
    bytes[0x02] = 0xB0; bytes[0x03] = 0x00; // indirect jump through table
    bytes[0x10] = 0x42; bytes[0x11] = 0xC3;
    bytes[0x14] = 0x42; bytes[0x15] = 0xC3;
    for (size_t target : {size_t{0x20}, size_t{0x30}, size_t{0x40}}) {
        bytes[target] = 0x42; bytes[target + 1] = 0xC3;
    }
    std::memcpy(bytes.data() + 0x60, "HELLO\0", 6);
    put64(bytes, 0x80, kBase + 0x20);
    put64(bytes, 0x88, kBase + 0x30);
    put64(bytes, 0x90, kBase + 0x40);
    put64(bytes, 0xA0, kBase + 0x10);
    put64(bytes, 0xA8, kBase + 0x14);
    std::fill(bytes.begin() + 0xC0, bytes.begin() + 0xD0, 0xCC);
    bytes[0xE0] = 0xF3; bytes[0xE1] = 0x0F; bytes[0xE2] = 0x1E; bytes[0xE3] = 0xFA;
    bytes[0xE4] = 0xC3;

    const std::string path = "ds_codedata_tmp.bin";
    { std::ofstream f(path, std::ios::binary); f.write((const char*)bytes.data(), bytes.size()); }
    BinaryFile bin;
    CHECK(bin.loadRaw(path, kBase), "load raw executable fixture");
    FixtureDis dis;
    const std::vector<CodeDataFunctionInput> functions = {{kBase, 8}};
    const std::vector<CodeDataStringInput> strings = {{kBase + 0x60, 6, false}};
    DecoderConfig x64Decoder;
    x64Decoder.arch = Arch::X64;
    const CodeDataMap map = ClassifyCodeData(bin, dis, x64Decoder, functions, strings);

    auto kindAt = [&](uint64_t address) {
        const CodeDataSpan* span = map.find(address);
        return span ? span->kind : CodeDataKind::Unknown;
    };
    CHECK(kindAt(kBase) == CodeDataKind::Code, "authoritative root is recursively classified as code");
    CHECK(kindAt(kBase + 0x10) == CodeDataKind::Code &&
          kindAt(kBase + 0x14) == CodeDataKind::Code,
          "indirect jump-table case targets become reachable code");
    CHECK(kindAt(kBase + 0x60) == CodeDataKind::String,
          "referenced executable-section string is typed data");
    CHECK(kindAt(kBase + 0x80) == CodeDataKind::PointerTable,
          "consecutive executable pointers form a code-pointer/vtable span");
    CHECK(map.find(kBase + 0x80) && map.find(kBase + 0x80)->elementWidth == 8,
          "64-bit pointer table retains dq element width");
    CHECK(kindAt(kBase + 0xA0) == CodeDataKind::JumpTable,
          "indirect branch upgrades its target array to a jump table");
    CHECK(kindAt(kBase + 0xC0) == CodeDataKind::Padding,
          "INT3 linker-fill run is classified as padding");
    CHECK(kindAt(kBase + 0xE0) == CodeDataKind::Code,
          "decoder-confirmed endbr64 gap seed is traversed as code");
    CHECK(kindAt(kBase + 0xF0) == CodeDataKind::Unknown,
          "unproved bytes remain honest Unknown rather than forced data/code");

    auto hasSeed = [&](uint64_t address) {
        return std::any_of(map.functionSeeds.begin(), map.functionSeeds.end(),
                           [&](const auto& seed) { return seed.address == address; });
    };
    CHECK(hasSeed(kBase + 0x20) && hasSeed(kBase + 0x30) && hasSeed(kBase + 0x40),
          "vtable/code-pointer targets are emitted as indirect function seeds");
    CHECK(hasSeed(kBase + 0xE0), "endbr64 landing pad is emitted as an indirect function seed");

    uint64_t total = 0, expected = kBase;
    for (const CodeDataSpan& span : map.spans) {
        CHECK(span.address == expected, "classification partition has no gaps or overlap");
        total += span.size; expected += span.size;
    }
    CHECK(total == bytes.size() && map.stats.executableBytes == bytes.size(),
          "classification spans cover every mapped executable byte exactly once");
    CHECK(map.stats.codeBytes && map.stats.dataBytes && map.stats.unknownBytes,
          "summary accounts independently for code, typed data, and unknown bytes");
    CHECK(CodeDataSummary(map).find("indirect seed") != std::string::npos,
          "human summary reports indirect-function recovery");

    // Raw files have no loader-owned byte order. The analyst's DecoderConfig is
    // therefore authoritative for pointer and jump-table reads.
    std::vector<uint8_t> beBytes(0x80, 0x42);
    put64be(beBytes, 0x00, kBase + 0x40);
    put64be(beBytes, 0x08, kBase + 0x50);
    put64be(beBytes, 0x10, kBase + 0x60);
    for (size_t target : {size_t{0x40}, size_t{0x50}, size_t{0x60}})
        beBytes[target] = 0xC3;
    const std::string bePath = "ds_codedata_be_tmp.bin";
    { std::ofstream f(bePath, std::ios::binary); f.write((const char*)beBytes.data(), beBytes.size()); }
    BinaryFile beBin;
    CHECK(beBin.loadRaw(bePath, kBase), "load big-endian raw pointer fixture");
    DecoderConfig beDecoder;
    beDecoder.engine = Engine::Capstone;
    beDecoder.arch = Arch::PPC64;
    beDecoder.byteOrder = ByteOrder::Big;
    const CodeDataMap beMap = ClassifyCodeData(beBin, dis, beDecoder, {}, {});
    CHECK(beMap.find(kBase) && beMap.find(kBase)->kind == CodeDataKind::PointerTable,
          "Raw big-endian DecoderConfig controls aligned code-pointer reads");
    DecoderConfig wrongEndian = beDecoder;
    wrongEndian.byteOrder = ByteOrder::Little;
    const CodeDataMap wrongEndianMap =
        ClassifyCodeData(beBin, dis, wrongEndian, {}, {});
    CHECK(!wrongEndianMap.find(kBase) ||
          wrongEndianMap.find(kBase)->kind != CodeDataKind::PointerTable,
          "same Raw bytes are not silently reinterpreted as little-endian pointers");

    // A resolver cap must not turn a successfully recovered prefix into a
    // silently complete table. Keep all 1,024 bounded targets classified and
    // traversable, but propagate the structured truncation evidence to the map.
    constexpr size_t kCappedEntries = 1024;
    constexpr size_t kTableOffset = 0xA0;
    constexpr size_t kTargetOffset = 0x2200;
    std::vector<uint8_t> cappedBytes(0x2300, 0x42);
    cappedBytes[0] = 0xB0; cappedBytes[1] = 0x00;
    for (size_t i = 0; i <= kCappedEntries; ++i)
        put64(cappedBytes, kTableOffset + i * sizeof(uint64_t), kBase + kTargetOffset);
    cappedBytes[kTargetOffset] = 0xC3;
    const std::string cappedPath = "ds_codedata_capped_table_tmp.bin";
    { std::ofstream f(cappedPath, std::ios::binary);
      f.write((const char*)cappedBytes.data(), cappedBytes.size()); }
    BinaryFile cappedBin;
    CHECK(cappedBin.loadRaw(cappedPath, kBase), "load capped jump-table fixture");
    const CodeDataMap cappedMap = ClassifyCodeData(
        cappedBin, dis, x64Decoder, {{kBase, 2}}, {});
    const CodeDataSpan* cappedTable = cappedMap.find(kBase + kTableOffset);
    CHECK(cappedMap.truncated,
          "a jump table that reaches the shared 1,024-entry cap marks the map truncated");
    CHECK(cappedMap.truncationReason.find("jump table") != std::string::npos &&
          cappedMap.truncationReason.find("1024 decoder-valid") != std::string::npos,
          "classifier preserves the resolver's jump-table truncation evidence");
    CHECK(cappedTable && cappedTable->kind == CodeDataKind::JumpTable &&
          cappedTable->size == kCappedEntries * sizeof(uint64_t),
          "all bounded jump-table entries remain classified despite truncation");
    CHECK(cappedMap.find(kBase + kTargetOffset) &&
          cappedMap.find(kBase + kTargetOffset)->kind == CodeDataKind::Code,
          "bounded jump-table targets remain available to recursive traversal");

    std::remove(path.c_str());
    std::remove(bePath.c_str());
    std::remove(cappedPath.c_str());
    if (g_fail) { std::printf("codedata_classifier_test: %d failure(s)\n", g_fail); return 1; }
    std::printf("codedata_classifier_test: all checks passed\n");
    return 0;
}
