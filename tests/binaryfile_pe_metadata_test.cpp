// Focused PE metadata regressions for BinaryFile: TLS callbacks, delay-load
// imports, CodeView/RSDS, security-relevant load configuration, and x64 unwind
// records. Fixtures are synthetic and include truncated/hostile directory data.
//
// Build (VS dev shell, from project root):
//   cl /std:c++20 /EHsc /I src tests\binaryfile_pe_metadata_test.cpp ^
//      src\Core\BinaryFile.cpp src\Core\JvmClass.cpp

#include "Core/BinaryFile.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

template <typename T>
static void put(std::vector<uint8_t>& bytes, size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

static void putString(std::vector<uint8_t>& bytes, size_t offset,
                      const char* value, bool terminator = true) {
    const size_t length = std::strlen(value);
    std::memcpy(bytes.data() + offset, value, length);
    if (terminator) bytes[offset + length] = 0;
}

constexpr uint64_t kImageBase = 0x140000000ull;
static size_t rdataOffset(uint32_t rva) { return 0x400u + (rva - 0x2000u); }

static std::vector<uint8_t> buildMetadataPE() {
    std::vector<uint8_t> bytes(0x1400, 0);
    bytes[0] = 'M'; bytes[1] = 'Z';
    constexpr uint32_t pe = 0x80;
    put<uint32_t>(bytes, 0x3C, pe);
    put<uint32_t>(bytes, pe, 0x00004550u); // PE\0\0

    const size_t coff = pe + 4;
    put<uint16_t>(bytes, coff + 0, 0x8664); // AMD64
    put<uint16_t>(bytes, coff + 2, 2);
    put<uint16_t>(bytes, coff + 16, 0xF0);
    put<uint16_t>(bytes, coff + 18, 0x0022);

    const size_t opt = coff + 20;
    put<uint16_t>(bytes, opt + 0, 0x20B);
    put<uint32_t>(bytes, opt + 16, 0x1000);
    put<uint64_t>(bytes, opt + 24, kImageBase);
    put<uint32_t>(bytes, opt + 32, 0x1000);
    put<uint32_t>(bytes, opt + 36, 0x200);
    put<uint32_t>(bytes, opt + 56, 0x3000);
    put<uint32_t>(bytes, opt + 60, 0x200);
    put<uint32_t>(bytes, opt + 108, 16); // NumberOfRvaAndSizes
    auto directory = [&](uint32_t index, uint32_t rva, uint32_t size) {
        put<uint32_t>(bytes, opt + 112 + static_cast<size_t>(index) * 8, rva);
        put<uint32_t>(bytes, opt + 116 + static_cast<size_t>(index) * 8, size);
    };
    directory(3, 0x2000, 36);   // exception/runtime function table
    directory(6, 0x2100, 28);   // debug
    directory(9, 0x2200, 40);   // TLS64
    directory(10, 0x2300, 0x94);// load config64 through GuardFlags
    directory(13, 0x2400, 64);  // delay import + null descriptor

    const size_t text = opt + 0xF0;
    putString(bytes, text, ".text");
    put<uint32_t>(bytes, text + 8, 0x200);
    put<uint32_t>(bytes, text + 12, 0x1000);
    put<uint32_t>(bytes, text + 16, 0x200);
    put<uint32_t>(bytes, text + 20, 0x200);
    put<uint32_t>(bytes, text + 36, 0x60000020u);

    const size_t rdata = text + 40;
    putString(bytes, rdata, ".rdata");
    put<uint32_t>(bytes, rdata + 8, 0x1000);
    put<uint32_t>(bytes, rdata + 12, 0x2000);
    put<uint32_t>(bytes, rdata + 16, 0x1000);
    put<uint32_t>(bytes, rdata + 20, 0x400);
    put<uint32_t>(bytes, rdata + 36, 0x40000040u);

    // Three runtime entries: ordinary EHANDLER, CHAININFO, and indirect.
    const size_t pdata = rdataOffset(0x2000);
    put<uint32_t>(bytes, pdata + 0, 0x1000);
    put<uint32_t>(bytes, pdata + 4, 0x1020);
    put<uint32_t>(bytes, pdata + 8, 0x2600);
    put<uint32_t>(bytes, pdata + 12, 0x1020);
    put<uint32_t>(bytes, pdata + 16, 0x1040);
    put<uint32_t>(bytes, pdata + 20, 0x2620);
    put<uint32_t>(bytes, pdata + 24, 0x1040);
    put<uint32_t>(bytes, pdata + 28, 0x1060);
    put<uint32_t>(bytes, pdata + 32, 0x2641); // RVA of parent RUNTIME_FUNCTION | 1

    const size_t unwind1 = rdataOffset(0x2600);
    bytes[unwind1 + 0] = static_cast<uint8_t>((1u << 3) | 1u); // EHANDLER, version 1
    bytes[unwind1 + 1] = 5;
    bytes[unwind1 + 2] = 2;
    bytes[unwind1 + 3] = 0x52; // frame offset 5, register 2
    put<uint16_t>(bytes, unwind1 + 4, 0x1234);
    put<uint16_t>(bytes, unwind1 + 6, 0xABCD);
    put<uint32_t>(bytes, unwind1 + 8, 0x1050); // handler RVA

    const size_t unwind2 = rdataOffset(0x2620);
    bytes[unwind2 + 0] = static_cast<uint8_t>((4u << 3) | 1u); // CHAININFO, version 1
    bytes[unwind2 + 1] = 3;
    bytes[unwind2 + 2] = 1;
    bytes[unwind2 + 3] = 0;
    put<uint16_t>(bytes, unwind2 + 4, 0x2233);
    put<uint32_t>(bytes, unwind2 + 8, 0x1000);
    put<uint32_t>(bytes, unwind2 + 12, 0x1020);
    put<uint32_t>(bytes, unwind2 + 16, 0x2600);
    const size_t indirectParent = rdataOffset(0x2640);
    put<uint32_t>(bytes, indirectParent + 0, 0x1000);
    put<uint32_t>(bytes, indirectParent + 4, 0x1020);
    put<uint32_t>(bytes, indirectParent + 8, 0x2600);

    // One RSDS CodeView record.
    const char pdbPath[] = "C:\\symbols\\sample.pdb";
    const uint32_t rsdsSize = 24u + static_cast<uint32_t>(sizeof(pdbPath));
    const size_t debug = rdataOffset(0x2100);
    put<uint32_t>(bytes, debug + 4, 0x12345678);
    put<uint16_t>(bytes, debug + 8, 1);
    put<uint16_t>(bytes, debug + 10, 2);
    put<uint32_t>(bytes, debug + 12, 2); // IMAGE_DEBUG_TYPE_CODEVIEW
    put<uint32_t>(bytes, debug + 16, rsdsSize);
    put<uint32_t>(bytes, debug + 20, 0x2700);
    put<uint32_t>(bytes, debug + 24, static_cast<uint32_t>(rdataOffset(0x2700)));
    const size_t rsds = rdataOffset(0x2700);
    std::memcpy(bytes.data() + rsds, "RSDS", 4);
    for (uint8_t i = 0; i < 16; ++i) bytes[rsds + 4 + i] = static_cast<uint8_t>(i + 1);
    put<uint32_t>(bytes, rsds + 20, 7);
    std::memcpy(bytes.data() + rsds + 24, pdbPath, sizeof(pdbPath));

    // TLS directory and callback array.
    const size_t tls = rdataOffset(0x2200);
    put<uint64_t>(bytes, tls + 0, kImageBase + 0x2800);
    put<uint64_t>(bytes, tls + 8, kImageBase + 0x2810);
    put<uint64_t>(bytes, tls + 16, kImageBase + 0x2820);
    put<uint64_t>(bytes, tls + 24, kImageBase + 0x2500);
    put<uint32_t>(bytes, tls + 32, 3);
    put<uint32_t>(bytes, tls + 36, 0x00100000);
    const size_t callbacks = rdataOffset(0x2500);
    put<uint64_t>(bytes, callbacks + 0, kImageBase + 0x1000);
    put<uint64_t>(bytes, callbacks + 8, kImageBase + 0x1050);
    put<uint64_t>(bytes, callbacks + 16, 0);

    // Load config through GuardFlags.
    const size_t loadConfig = rdataOffset(0x2300);
    put<uint32_t>(bytes, loadConfig + 0, 0x94);
    put<uint32_t>(bytes, loadConfig + 4, 0x87654321);
    put<uint16_t>(bytes, loadConfig + 8, 3);
    put<uint16_t>(bytes, loadConfig + 10, 1);
    put<uint16_t>(bytes, loadConfig + 78, 0x0800);
    put<uint64_t>(bytes, loadConfig + 88, kImageBase + 0x2830); // security cookie
    put<uint64_t>(bytes, loadConfig + 96, kImageBase + 0x2840); // SafeSEH table
    put<uint64_t>(bytes, loadConfig + 104, 2);
    put<uint64_t>(bytes, loadConfig + 112, kImageBase + 0x1010); // Guard check
    put<uint64_t>(bytes, loadConfig + 120, kImageBase + 0x1020); // Guard dispatch
    put<uint64_t>(bytes, loadConfig + 128, kImageBase + 0x2850); // Guard table
    put<uint64_t>(bytes, loadConfig + 136, 3);
    put<uint32_t>(bytes, loadConfig + 144, 0x00000500);

    // Delay-load descriptor. The null descriptor is supplied by zero-fill.
    const size_t delay = rdataOffset(0x2400);
    put<uint32_t>(bytes, delay + 0, 1);      // dlattrRva
    put<uint32_t>(bytes, delay + 4, 0x2480); // DLL name RVA
    put<uint32_t>(bytes, delay + 8, 0x2490); // module handle RVA
    put<uint32_t>(bytes, delay + 12, 0x24A0);// IAT RVA
    put<uint32_t>(bytes, delay + 16, 0x24C0);// INT RVA
    put<uint32_t>(bytes, delay + 28, 0xAABBCCDD);
    putString(bytes, rdataOffset(0x2480), "DELAY.dll");
    const size_t delayInt = rdataOffset(0x24C0);
    put<uint64_t>(bytes, delayInt + 0, 0x24E0);
    put<uint64_t>(bytes, delayInt + 8, 0x800000000000002Aull);
    put<uint64_t>(bytes, delayInt + 16, 0);
    const size_t delayName = rdataOffset(0x24E0);
    put<uint16_t>(bytes, delayName, 9); // hint
    putString(bytes, delayName + 2, "DelayedFn");
    return bytes;
}

static std::vector<uint8_t> buildMetadataPE32() {
    constexpr uint64_t base = 0x400000;
    std::vector<uint8_t> bytes(0x1000, 0);
    bytes[0] = 'M'; bytes[1] = 'Z';
    constexpr uint32_t pe = 0x80;
    put<uint32_t>(bytes, 0x3C, pe);
    put<uint32_t>(bytes, pe, 0x00004550u);
    const size_t coff = pe + 4;
    put<uint16_t>(bytes, coff + 0, 0x014C);
    put<uint16_t>(bytes, coff + 2, 2);
    put<uint16_t>(bytes, coff + 16, 0xE0);
    put<uint16_t>(bytes, coff + 18, 0x0102);

    const size_t opt = coff + 20;
    put<uint16_t>(bytes, opt + 0, 0x10B);
    put<uint32_t>(bytes, opt + 16, 0x1000);
    put<uint32_t>(bytes, opt + 28, static_cast<uint32_t>(base));
    put<uint32_t>(bytes, opt + 32, 0x1000);
    put<uint32_t>(bytes, opt + 36, 0x200);
    put<uint32_t>(bytes, opt + 56, 0x3000);
    put<uint32_t>(bytes, opt + 60, 0x200);
    put<uint32_t>(bytes, opt + 92, 16);
    auto directory = [&](uint32_t index, uint32_t rva, uint32_t size) {
        put<uint32_t>(bytes, opt + 96 + static_cast<size_t>(index) * 8, rva);
        put<uint32_t>(bytes, opt + 100 + static_cast<size_t>(index) * 8, size);
    };
    directory(9, 0x2200, 24);
    directory(10, 0x2300, 92);
    directory(13, 0x2400, 64);

    const size_t text = opt + 0xE0;
    putString(bytes, text, ".text");
    put<uint32_t>(bytes, text + 8, 0x200);
    put<uint32_t>(bytes, text + 12, 0x1000);
    put<uint32_t>(bytes, text + 16, 0x200);
    put<uint32_t>(bytes, text + 20, 0x200);
    put<uint32_t>(bytes, text + 36, 0x60000020u);
    const size_t rdata = text + 40;
    putString(bytes, rdata, ".rdata");
    put<uint32_t>(bytes, rdata + 8, 0xC00);
    put<uint32_t>(bytes, rdata + 12, 0x2000);
    put<uint32_t>(bytes, rdata + 16, 0xC00);
    put<uint32_t>(bytes, rdata + 20, 0x400);
    put<uint32_t>(bytes, rdata + 36, 0x40000040u);

    const size_t tls = rdataOffset(0x2200);
    put<uint32_t>(bytes, tls + 0, static_cast<uint32_t>(base + 0x2800));
    put<uint32_t>(bytes, tls + 4, static_cast<uint32_t>(base + 0x2810));
    put<uint32_t>(bytes, tls + 8, static_cast<uint32_t>(base + 0x2820));
    put<uint32_t>(bytes, tls + 12, static_cast<uint32_t>(base + 0x2500));
    put<uint32_t>(bytes, tls + 16, 1);
    put<uint32_t>(bytes, tls + 20, 0);
    put<uint32_t>(bytes, rdataOffset(0x2500), static_cast<uint32_t>(base + 0x1000));
    put<uint32_t>(bytes, rdataOffset(0x2500) + 4, 0);

    const size_t config = rdataOffset(0x2300);
    put<uint32_t>(bytes, config + 0, 92);
    put<uint16_t>(bytes, config + 54, 0x0800);
    put<uint32_t>(bytes, config + 60, static_cast<uint32_t>(base + 0x2830));
    put<uint32_t>(bytes, config + 64, static_cast<uint32_t>(base + 0x2840));
    put<uint32_t>(bytes, config + 68, 4);
    put<uint32_t>(bytes, config + 72, static_cast<uint32_t>(base + 0x1010));
    put<uint32_t>(bytes, config + 76, static_cast<uint32_t>(base + 0x1020));
    put<uint32_t>(bytes, config + 80, static_cast<uint32_t>(base + 0x2850));
    put<uint32_t>(bytes, config + 84, 6);
    put<uint32_t>(bytes, config + 88, 0x500);

    // Exercise the legacy descriptor form, whose fields and name thunks are VAs.
    const size_t delay = rdataOffset(0x2400);
    put<uint32_t>(bytes, delay + 0, 0);
    put<uint32_t>(bytes, delay + 4, static_cast<uint32_t>(base + 0x2480));
    put<uint32_t>(bytes, delay + 8, static_cast<uint32_t>(base + 0x2490));
    put<uint32_t>(bytes, delay + 12, static_cast<uint32_t>(base + 0x24A0));
    put<uint32_t>(bytes, delay + 16, static_cast<uint32_t>(base + 0x24C0));
    putString(bytes, rdataOffset(0x2480), "LEGACY.dll");
    put<uint32_t>(bytes, rdataOffset(0x24C0), static_cast<uint32_t>(base + 0x24E0));
    put<uint32_t>(bytes, rdataOffset(0x24C0) + 4, 0x80000005u);
    put<uint32_t>(bytes, rdataOffset(0x24C0) + 8, 0);
    put<uint16_t>(bytes, rdataOffset(0x24E0), 0);
    putString(bytes, rdataOffset(0x24E0) + 2, "LegacyFn");
    return bytes;
}

static bool loadBytes(BinaryFile& binary, const std::vector<uint8_t>& bytes,
                      const char* path) {
    {
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    const bool loaded = binary.load(path);
    std::remove(path);
    return loaded;
}

static void validMetadata() {
    BinaryFile binary;
    CHECK(loadBytes(binary, buildMetadataPE(), "pe_metadata_valid.bin"));
    CHECK(binary.format() == BinFormat::PE32Plus);

    const auto& tls = binary.peTls();
    CHECK(tls.present && tls.directoryValid);
    CHECK(tls.directoryRVA == 0x2200 && tls.directorySize == 40);
    CHECK(tls.rawDataRangeValid && tls.rawDataStartVA == kImageBase + 0x2800);
    CHECK(tls.indexVA == kImageBase + 0x2820);
    CHECK(tls.callbackTableMapped && tls.callbacksTerminated && !tls.callbacksTruncated);
    CHECK(tls.callbacks.size() == 2);
    if (tls.callbacks.size() == 2) {
        CHECK(tls.callbacks[0] == kImageBase + 0x1000);
        CHECK(tls.callbacks[1] == kImageBase + 0x1050);
    }

    const auto& delays = binary.delayImports();
    CHECK(delays.size() == 1);
    if (!delays.empty()) {
        const auto& delay = delays[0];
        CHECK(delay.descriptorValid && delay.fieldsAreRVA && delay.dllNameTerminated);
        CHECK(delay.dll == "DELAY.dll" && delay.timestamp == 0xAABBCCDD);
        CHECK(delay.moduleHandleVA == kImageBase + 0x2490);
        CHECK(delay.symbolsTerminated && !delay.symbolsTruncated);
        CHECK(delay.symbols.size() == 2);
        if (delay.symbols.size() == 2) {
            CHECK(delay.symbols[0].name == "DelayedFn" && !delay.symbols[0].byOrdinal);
            CHECK(delay.symbols[0].iatVA == kImageBase + 0x24A0);
            CHECK(delay.symbols[1].byOrdinal && delay.symbols[1].ordinal == 42);
            CHECK(delay.symbols[1].name == "#42");
        }
    }
    size_t normalizedDelayRows = 0;
    for (const auto& imported : binary.imports())
        if (imported.delayed) ++normalizedDelayRows;
    CHECK(normalizedDelayRows == 2);

    const auto& debug = binary.peDebugEntries();
    CHECK(debug.size() == 1);
    if (!debug.empty()) {
        CHECK(debug[0].payloadAvailable && debug[0].payloadFileOffsetValid);
        CHECK(debug[0].codeViewRsds && debug[0].codeViewAge == 7);
        CHECK(debug[0].codeViewGuid == "04030201-0605-0807-090A-0B0C0D0E0F10");
        CHECK(debug[0].pdbPath == "C:\\symbols\\sample.pdb");
        CHECK(debug[0].pdbPathTerminated);
    }

    const auto& config = binary.peLoadConfig();
    CHECK(config.present && config.headerValid && config.declaredSize == 0x94);
    CHECK(config.dependentLoadFlagsPresent && config.dependentLoadFlags == 0x0800);
    CHECK(config.securityCookiePresent && config.securityCookieMapped);
    CHECK(config.securityCookieVA == kImageBase + 0x2830);
    CHECK(config.seHandlerTablePresent && config.seHandlerTableMapped && config.seHandlerCount == 2);
    CHECK(config.guardCfCheckPresent && config.guardCfCheckMapped);
    CHECK(config.guardCfDispatchPresent && config.guardCfDispatchMapped);
    CHECK(config.guardCfTablePresent && config.guardCfTableMapped);
    CHECK(config.guardCfFunctionCount == 3);
    CHECK(config.guardFlagsPresent && config.guardFlags == 0x500);

    const auto& runtime = binary.runtimeFunctions();
    CHECK(runtime.size() == 3);
    if (runtime.size() == 3) {
        CHECK(runtime[0].rangeValid && runtime[0].unwindInfoValid);
        CHECK(runtime[0].unwindVersion == 1 && runtime[0].unwindFlags == 1);
        CHECK(runtime[0].prologSize == 5 && runtime[0].frameRegister == 2 && runtime[0].frameOffset == 5);
        CHECK(runtime[0].unwindCodesComplete && runtime[0].unwindCodeSlots.size() == 2);
        CHECK(runtime[0].exceptionHandlerPresent && runtime[0].exceptionHandlerMapped);
        CHECK(runtime[0].exceptionHandlerVA == kImageBase + 0x1050);
        CHECK(runtime[1].chainedInfoPresent && runtime[1].chainedInfoValid);
        CHECK(runtime[1].chainedBeginRVA == 0x1000 && runtime[1].chainedEndRVA == 0x1020);
        CHECK(runtime[2].indirectEntry && runtime[2].chainedInfoValid);
    }
    const auto ranges = binary.pdataRanges();
    CHECK(ranges.size() == 1);
    if (!ranges.empty())
        CHECK(ranges[0].first == kImageBase + 0x1000 && ranges[0].second == kImageBase + 0x1020);
}

static void hostileMetadata() {
    auto bytes = buildMetadataPE();
    constexpr size_t opt = 0x98;
    // Structurally present, but too short to borrow bytes following each dir.
    put<uint32_t>(bytes, opt + 112 + 9 * 8 + 4, 8);  // TLS size
    put<uint32_t>(bytes, opt + 112 + 10 * 8 + 4, 12);// load-config size
    put<uint32_t>(bytes, rdataOffset(0x2300), 0xFFFFFFFFu);

    // RSDS payload claims an impossible span; no read should be attempted.
    const size_t debug = rdataOffset(0x2100);
    put<uint32_t>(bytes, debug + 16, 0xFFFFFFFFu);
    put<uint32_t>(bytes, debug + 20, 0x2FFF);
    put<uint32_t>(bytes, debug + 24, 0x13FF);

    // Delay descriptor has an unterminated DLL name and maximal directory size;
    // the zero second descriptor still terminates the bounded walk.
    put<uint32_t>(bytes, opt + 112 + 13 * 8 + 4, 0xFFFFFFFFu);
    put<uint32_t>(bytes, rdataOffset(0x2400) + 4, 0x2E00u);
    std::fill(bytes.begin() + rdataOffset(0x2E00), bytes.end(), static_cast<uint8_t>('A'));

    BinaryFile binary;
    CHECK(loadBytes(binary, bytes, "pe_metadata_hostile.bin"));
    CHECK(binary.peTls().present && !binary.peTls().directoryValid);
    CHECK(binary.peTls().callbacks.empty());
    CHECK(binary.peLoadConfig().present && binary.peLoadConfig().headerValid);
    CHECK(!binary.peLoadConfig().securityCookiePresent);
    CHECK(binary.peDebugEntries().size() == 1);
    if (!binary.peDebugEntries().empty()) {
        CHECK(!binary.peDebugEntries()[0].payloadAvailable);
        CHECK(!binary.peDebugEntries()[0].codeViewRsds);
    }
    CHECK(binary.delayImports().size() == 1);
    if (!binary.delayImports().empty()) {
        CHECK(!binary.delayImports()[0].descriptorValid && binary.delayImports()[0].symbols.empty());
        CHECK(!binary.delayImports()[0].dllNameTerminated);
    }

    // The runtime directory remains independently valid despite other malformed
    // tables, demonstrating that a bad directory cannot poison later parsers.
    CHECK(binary.runtimeFunctions().size() == 3);
}

static void pe32LayoutsAndLegacyDelayDescriptor() {
    BinaryFile binary;
    CHECK(loadBytes(binary, buildMetadataPE32(), "pe_metadata_32.bin"));
    CHECK(binary.format() == BinFormat::PE32 && !binary.is64Bit());
    CHECK(binary.peTls().directoryValid && binary.peTls().callbacks.size() == 1);
    if (!binary.peTls().callbacks.empty())
        CHECK(binary.peTls().callbacks[0] == 0x401000);

    const auto& config = binary.peLoadConfig();
    CHECK(config.headerValid && config.securityCookieVA == 0x402830);
    CHECK(config.securityCookieMapped && config.seHandlerCount == 4);
    CHECK(config.guardCfCheckFunctionVA == 0x401010 && config.guardCfCheckMapped);
    CHECK(config.guardCfDispatchFunctionVA == 0x401020 && config.guardCfDispatchMapped);
    CHECK(config.guardCfFunctionTableVA == 0x402850 && config.guardCfFunctionCount == 6);
    CHECK(config.guardFlags == 0x500);

    CHECK(binary.delayImports().size() == 1);
    if (!binary.delayImports().empty()) {
        const auto& delay = binary.delayImports()[0];
        CHECK(delay.descriptorValid && !delay.fieldsAreRVA && delay.dll == "LEGACY.dll");
        CHECK(delay.symbols.size() == 2 && delay.symbolsTerminated);
        if (delay.symbols.size() == 2) {
            CHECK(delay.symbols[0].name == "LegacyFn");
            CHECK(delay.symbols[1].byOrdinal && delay.symbols[1].ordinal == 5);
        }
    }
    CHECK(binary.runtimeFunctions().empty()); // x64-only model by design

    binary.clear();
    CHECK(!binary.peTls().present && binary.delayImports().empty());
    CHECK(binary.peDebugEntries().empty() && !binary.peLoadConfig().present);
    CHECK(binary.runtimeFunctions().empty());
}

static void unterminatedRsdsPath() {
    auto bytes = buildMetadataPE();
    const size_t debug = rdataOffset(0x2100);
    put<uint32_t>(bytes, debug + 16, 29); // RSDS header + exactly five path bytes
    put<uint32_t>(bytes, debug + 20, 0);  // force disk PointerToRawData fallback
    const size_t path = rdataOffset(0x2700) + 24;
    std::memcpy(bytes.data() + path, "abcde", 5);
    BinaryFile binary;
    CHECK(loadBytes(binary, bytes, "pe_metadata_unterminated.bin"));
    CHECK(binary.peDebugEntries().size() == 1);
    if (!binary.peDebugEntries().empty()) {
        CHECK(binary.peDebugEntries()[0].codeViewRsds);
        CHECK(binary.peDebugEntries()[0].pdbPath == "abcde");
        CHECK(!binary.peDebugEntries()[0].pdbPathTerminated);
    }
}

static void relocationDirectoryBoundsAndHighAdjPairing() {
    auto bytes = buildMetadataPE();
    constexpr size_t opt = 0x98;
    constexpr uint32_t relocRVA = 0x2900;
    constexpr uint32_t firstBlockSize = 16; // header + four 16-bit slots

    // The directory contains the complete first block and only the header of
    // the second block. Bytes following the declared directory remain mapped,
    // so the parser must enforce the directory size independently of section
    // availability.
    put<uint32_t>(bytes, opt + 112 + 5 * 8, relocRVA);
    put<uint32_t>(bytes, opt + 116 + 5 * 8, firstBlockSize + 8);

    const size_t first = rdataOffset(relocRVA);
    put<uint32_t>(bytes, first + 0, 0x1000);
    put<uint32_t>(bytes, first + 4, firstBlockSize);
    put<uint16_t>(bytes, first + 8, 0x4010);  // HIGHADJ at RVA 0x1010
    put<uint16_t>(bytes, first + 10, 0xA123); // signed adjustment, not DIR64
    put<uint16_t>(bytes, first + 12, 0xA020); // DIR64 at RVA 0x1020
    put<uint16_t>(bytes, first + 14, 0x0000); // ABSOLUTE alignment padding

    const size_t second = first + firstBlockSize;
    put<uint32_t>(bytes, second + 0, 0x1000);
    put<uint32_t>(bytes, second + 4, 10);
    put<uint16_t>(bytes, second + 8, 0xA030); // outside the declared directory

    BinaryFile binary;
    CHECK(loadBytes(binary, bytes, "pe_metadata_reloc_bounds.bin"));
    const auto& relocations = binary.relocations();
    CHECK(relocations.size() == 2);
    if (relocations.size() == 2) {
        CHECK(relocations[0].first == kImageBase + 0x1010 && relocations[0].second == 4);
        CHECK(relocations[1].first == kImageBase + 0x1020 && relocations[1].second == 10);
    }
}

int main() {
    validMetadata();
    pe32LayoutsAndLegacyDelayDescriptor();
    hostileMetadata();
    unterminatedRsdsPath();
    relocationDirectoryBoundsAndHighAdjPairing();
    if (!g_fail) std::printf("ALL PE METADATA TESTS PASSED\n");
    return g_fail ? 1 : 0;
}
