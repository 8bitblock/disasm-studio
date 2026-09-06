#include "Core/PeUnpack.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

using namespace ds;

static int g_failures = 0;

#define CHECK(expr) do { if (!(expr)) { \
    std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    ++g_failures; \
} } while (0)

template <class T>
static void put(std::vector<uint8_t>& bytes, size_t offset, T value) {
    if (offset + sizeof(T) <= bytes.size())
        std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

template <class T>
static T get(const std::vector<uint8_t>& bytes, size_t offset) {
    T value{};
    if (offset + sizeof(T) <= bytes.size())
        std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

static void putString(std::vector<uint8_t>& bytes, size_t offset,
                      const char* text, size_t capacity) {
    if (offset + capacity > bytes.size()) return;
    std::memset(bytes.data() + offset, 0, capacity);
    std::memcpy(bytes.data() + offset, text,
                std::min(capacity - 1, std::strlen(text)));
}

struct Fixture {
    std::vector<uint8_t> mapped;
    uint64_t preferredBase = 0x140000000ull;
    uint64_t runtimeBase = 0x180000000ull;
    uint32_t pe = 0x80;
    uint32_t opt = 0x98;
    uint32_t sectionTable = 0x188;
};

static void setDirectory(Fixture& fixture, uint32_t index,
                         uint32_t rva, uint32_t size) {
    const size_t directory = fixture.opt + 112 + index * 8ull;
    put<uint32_t>(fixture.mapped, directory, rva);
    put<uint32_t>(fixture.mapped, directory + 4, size);
}

static void setSection(Fixture& fixture, uint32_t index, const char* name,
                       uint32_t rva, uint32_t size, uint32_t characteristics) {
    const size_t section = fixture.sectionTable + index * 40ull;
    putString(fixture.mapped, section, name, 8);
    put<uint32_t>(fixture.mapped, section + 8, size);  // VirtualSize
    put<uint32_t>(fixture.mapped, section + 12, rva);
    put<uint32_t>(fixture.mapped, section + 16, size); // stale mapped RawSize
    put<uint32_t>(fixture.mapped, section + 20, rva);  // stale mapped RawOffset
    put<uint32_t>(fixture.mapped, section + 36, characteristics);
}

static Fixture buildMappedPe64() {
    Fixture fixture;
    fixture.mapped.assign(0x5000, 0);
    auto& b = fixture.mapped;

    put<uint16_t>(b, 0, 0x5a4d);
    put<uint32_t>(b, 0x3c, fixture.pe);
    put<uint32_t>(b, fixture.pe, 0x00004550);
    const uint32_t coff = fixture.pe + 4;
    put<uint16_t>(b, coff + 0, 0x8664); // AMD64
    put<uint16_t>(b, coff + 2, 4);
    put<uint32_t>(b, coff + 8, 0x4e00); // stale COFF symbol-table file offset
    put<uint32_t>(b, coff + 12, 7);
    put<uint16_t>(b, coff + 16, 0xf0);
    put<uint16_t>(b, coff + 18, 0x0022);

    const uint32_t opt = fixture.opt;
    put<uint16_t>(b, opt + 0, 0x20b);
    put<uint32_t>(b, opt + 16, 0x1000);
    put<uint64_t>(b, opt + 24, fixture.preferredBase);
    put<uint32_t>(b, opt + 32, 0x1000); // SectionAlignment
    put<uint32_t>(b, opt + 36, 0x200);  // FileAlignment
    put<uint32_t>(b, opt + 56, 0x5000); // SizeOfImage
    put<uint32_t>(b, opt + 60, 0x400);  // SizeOfHeaders, room for .dsimp header
    put<uint32_t>(b, opt + 64, 0x12345678); // stale checksum
    put<uint16_t>(b, opt + 68, 3);
    put<uint16_t>(b, opt + 70, 0x4040); // DYNAMIC_BASE | GUARD_CF
    put<uint32_t>(b, opt + 108, 16);

    setSection(fixture, 0, ".text",  0x1000, 0x600, 0x60000020u);
    setSection(fixture, 1, ".rdata", 0x2000, 0x800, 0x40000040u);
    setSection(fixture, 2, ".reloc", 0x3000, 0x200, 0x42000040u);
    setSection(fixture, 3, ".data",  0x4000, 0x200, 0xc0000040u);

    // Executable bytes and a loader-relocated DIR64 pointer.
    b[0x1000] = 0x55;
    b[0x1001] = 0x48;
    b[0x1002] = 0x89;
    b[0x1003] = 0xe5;
    b[0x1050] = 0xc3;
    put<uint64_t>(b, 0x1100, fixture.runtimeBase + 0x1234);

    // One intact original import. Its IAT currently contains a resolved address;
    // restoration must copy the original ILT name thunk back into it.
    setDirectory(fixture, 1, 0x2100, 40);
    put<uint32_t>(b, 0x2100 + 0, 0x2200); // OriginalFirstThunk
    put<uint32_t>(b, 0x2100 + 12, 0x2180);
    put<uint32_t>(b, 0x2100 + 16, 0x2220); // FirstThunk
    putString(b, 0x2180, "KERNEL32.dll", 32);
    put<uint64_t>(b, 0x2200, 0x2250);
    put<uint64_t>(b, 0x2208, 0);
    put<uint16_t>(b, 0x2250, 0);
    putString(b, 0x2252, "ExitProcess", 32);
    put<uint64_t>(b, 0x2220, 0x7fff12345678ull);
    put<uint64_t>(b, 0x2228, 0);

    // Security/bound-import directories are stale in a reconstructed image.
    setDirectory(fixture, 4, 0x4f00, 0x40);
    setDirectory(fixture, 11, 0x2600, 0x20);
    setDirectory(fixture, 6, 0x2500, 28);
    put<uint32_t>(b, 0x2500 + 20, 0x2500); // AddressOfRawData
    put<uint32_t>(b, 0x2500 + 24, 0x444);  // stale PointerToRawData

    // One relocation block: DIR64 at RVA 0x1100 plus ABSOLUTE padding.
    setDirectory(fixture, 5, 0x3000, 12);
    put<uint32_t>(b, 0x3000, 0x1000);
    put<uint32_t>(b, 0x3004, 12);
    put<uint16_t>(b, 0x3008, static_cast<uint16_t>((10u << 12) | 0x100));
    put<uint16_t>(b, 0x300a, 0);

    // IMAGE_LOAD_CONFIG_DIRECTORY64. Three image pointers are repairable and
    // one Guard CF pointer is hostile, forcing conservative CFG clearing.
    setDirectory(fixture, 10, 0x2400, 0xa0);
    put<uint32_t>(b, 0x2400, 0xa0);
    put<uint64_t>(b, 0x2400 + 0x58, fixture.runtimeBase + 0x2600); // cookie
    put<uint64_t>(b, 0x2400 + 0x70, fixture.runtimeBase + 0x2700); // check
    put<uint64_t>(b, 0x2400 + 0x78, 0xdeadbeefcafebabeull);        // invalid dispatch
    put<uint64_t>(b, 0x2400 + 0x80, fixture.runtimeBase + 0x2800); // function table
    put<uint64_t>(b, 0x2400 + 0x88, 7);                           // function count
    put<uint32_t>(b, 0x2400 + 0x90, 0x500);                       // guard flags

    // Observed-IAT slots live in the writable section.
    put<uint64_t>(b, 0x4100, 0x7fff11111111ull);
    put<uint64_t>(b, 0x4108, 0x7fff22222222ull);
    put<uint64_t>(b, 0x4110, 0x7fff33333333ull);
    return fixture;
}

struct DiskPe {
    const std::vector<uint8_t>& bytes;
    uint32_t pe = 0;
    uint32_t coff = 0;
    uint32_t opt = 0;
    uint32_t sections = 0;
    uint16_t sectionCount = 0;

    explicit DiskPe(const std::vector<uint8_t>& image) : bytes(image) {
        pe = get<uint32_t>(bytes, 0x3c);
        coff = pe + 4;
        opt = coff + 20;
        sectionCount = get<uint16_t>(bytes, coff + 2);
        sections = opt + get<uint16_t>(bytes, coff + 16);
    }

    size_t rvaToOffset(uint32_t rva) const {
        const uint32_t headers = get<uint32_t>(bytes, opt + 60);
        if (rva < headers && rva < bytes.size()) return rva;
        for (uint16_t i = 0; i < sectionCount; ++i) {
            const size_t section = sections + i * 40ull;
            const uint32_t va = get<uint32_t>(bytes, section + 12);
            const uint32_t virtualSize = get<uint32_t>(bytes, section + 8);
            const uint32_t rawSize = get<uint32_t>(bytes, section + 16);
            const uint32_t raw = get<uint32_t>(bytes, section + 20);
            const uint64_t span = std::max<uint32_t>(virtualSize, rawSize);
            if (rva >= va && static_cast<uint64_t>(rva - va) < span &&
                rva - va < rawSize && raw <= bytes.size() &&
                rva - va <= bytes.size() - raw)
                return static_cast<size_t>(raw + (rva - va));
        }
        return static_cast<size_t>(-1);
    }

    size_t section(const char* name) const {
        for (uint16_t i = 0; i < sectionCount; ++i) {
            const size_t offset = sections + i * 40ull;
            char actual[9]{};
            if (offset + 8 <= bytes.size())
                std::memcpy(actual, bytes.data() + offset, 8);
            if (std::string(actual) == name) return offset;
        }
        return static_cast<size_t>(-1);
    }

    uint32_t directoryRva(uint32_t index) const {
        return get<uint32_t>(bytes, opt + 112 + index * 8ull);
    }

    uint32_t directorySize(uint32_t index) const {
        return get<uint32_t>(bytes, opt + 112 + index * 8ull + 4);
    }

    std::string rvaString(uint32_t rva) const {
        const size_t offset = rvaToOffset(rva);
        std::string value;
        if (offset == static_cast<size_t>(-1)) return value;
        for (size_t i = offset; i < bytes.size() && bytes[i] && value.size() < 512; ++i)
            value.push_back(static_cast<char>(bytes[i]));
        return value;
    }
};

static bool hasIssue(const PeUnpackResult& result, const char* code) {
    for (const auto& issue : result.issues)
        if (issue.code == code) return true;
    return false;
}

int main() {
    const Fixture fixture = buildMappedPe64();
    const auto pristine = fixture.mapped;

    PeUnpackOptions options;
    options.runtimeImageBase = fixture.runtimeBase;
    options.hasOep = true;
    options.oepVA = fixture.runtimeBase + 0x1050;
    options.observedImports = {
        {fixture.runtimeBase + 0x4100, "KERNEL32.dll", "GetProcAddress", 0, false, 0x7fff11111111ull},
        {fixture.runtimeBase + 0x4108, "KERNEL32.dll", "", 7, true, 0x7fff22222222ull},
        {fixture.runtimeBase + 0x4110, "USER32.dll", "MessageBoxA", 0, false, 0x7fff33333333ull},
        // Already covered by the validated intact descriptor and must not be
        // duplicated in the synthetic import section.
        {fixture.runtimeBase + 0x2220, "KERNEL32.dll", "ExitProcess", 0, false, 0x7fff12345678ull},
        {fixture.runtimeBase + 0x6000, "BAD.dll", "OutsideImage", 0, false, 0}
    };

    const PeUnpackResult result = RebuildMappedPe(fixture.mapped, options);
    CHECK(fixture.mapped == pristine); // input is immutable
    CHECK(result.success);
    CHECK(!result.repairs.failureArtifactOnly);
    CHECK(result.rawMappedImage == pristine);
    CHECK(result.is64);
    CHECK(result.preferredImageBase == fixture.preferredBase);
    CHECK(result.outputImageBase == fixture.preferredBase);
    CHECK(result.entryRVA == 0x1050);
    CHECK(result.repairs.entryPointChanged);
    CHECK(result.repairs.sectionsRebuilt == 5);
    CHECK(result.repairs.relocationEntriesNormalized == 1);
    CHECK(result.repairs.importSlotsRestored == 1);
    CHECK(result.repairs.importsRebuilt == 3);
    CHECK(result.repairs.importRunsRebuilt == 2);
    CHECK(result.repairs.loadConfigPointersRepaired == 3);
    CHECK(result.repairs.loadConfigPointersCleared == 1);
    CHECK(result.repairs.securityDirectoryCleared);
    CHECK(result.repairs.checksumCleared);
    CHECK(hasIssue(result, "import-rejected"));
    CHECK(hasIssue(result, "cfg-cleared"));
    CHECK(hasIssue(result, "signature-cleared"));
    CHECK(hasIssue(result, "debug-cleared"));
    CHECK(hasIssue(result, "coff-symbols-cleared"));
    CHECK(result.report.find("result: reconstructed") != std::string::npos);

    if (result.success) {
        const DiskPe disk(result.image);
        CHECK(get<uint16_t>(result.image, 0) == 0x5a4d);
        CHECK(get<uint32_t>(result.image, disk.pe) == 0x00004550);
        CHECK(disk.sectionCount == 5);
        CHECK(get<uint32_t>(result.image, disk.opt + 16) == 0x1050);
        CHECK(get<uint64_t>(result.image, disk.opt + 24) == fixture.preferredBase);
        CHECK(get<uint32_t>(result.image, disk.opt + 64) == 0);
        CHECK((get<uint16_t>(result.image, disk.opt + 70) & 0x4000u) == 0);
        CHECK(disk.directoryRva(4) == 0 && disk.directorySize(4) == 0);
        CHECK(disk.directoryRva(6) == 0 && disk.directorySize(6) == 0);
        CHECK(disk.directoryRva(11) == 0 && disk.directorySize(11) == 0);
        CHECK(disk.directoryRva(1) != 0 && disk.directorySize(1) == 80);
        CHECK(disk.directoryRva(12) == 0x2220 && disk.directorySize(12) == 0x1f00);
        CHECK(get<uint32_t>(result.image, disk.coff + 8) == 0);
        CHECK(get<uint32_t>(result.image, disk.coff + 12) == 0);
        CHECK(get<uint32_t>(result.image, disk.opt + 56) == 0x6000);

        // Every materialized section has a normal aligned disk layout.
        for (uint16_t i = 0; i < disk.sectionCount; ++i) {
            const size_t section = disk.sections + i * 40ull;
            const uint32_t rva = get<uint32_t>(result.image, section + 12);
            const uint32_t rawSize = get<uint32_t>(result.image, section + 16);
            const uint32_t raw = get<uint32_t>(result.image, section + 20);
            CHECK((rva & 0xfffu) == 0);
            if (rawSize) {
                CHECK((rawSize & 0x1ffu) == 0);
                CHECK((raw & 0x1ffu) == 0);
                CHECK(raw <= result.image.size() && rawSize <= result.image.size() - raw);
            }
        }

        const size_t textPointer = disk.rvaToOffset(0x1100);
        CHECK(textPointer != static_cast<size_t>(-1));
        if (textPointer != static_cast<size_t>(-1))
            CHECK(get<uint64_t>(result.image, textPointer) == fixture.preferredBase + 0x1234);

        // The original resolved IAT was restored from its intact ILT and its
        // validated descriptor remains reachable alongside observed imports.
        const size_t oldIat = disk.rvaToOffset(0x2220);
        CHECK(oldIat != static_cast<size_t>(-1));
        if (oldIat != static_cast<size_t>(-1)) {
            CHECK(get<uint64_t>(result.image, oldIat) == 0x2250);
            CHECK(get<uint64_t>(result.image, oldIat + 8) == 0);
        }

        const size_t loadConfig = disk.rvaToOffset(0x2400);
        CHECK(loadConfig != static_cast<size_t>(-1));
        if (loadConfig != static_cast<size_t>(-1)) {
            CHECK(get<uint64_t>(result.image, loadConfig + 0x58) == fixture.preferredBase + 0x2600);
            CHECK(get<uint64_t>(result.image, loadConfig + 0x70) == fixture.preferredBase + 0x2700);
            CHECK(get<uint64_t>(result.image, loadConfig + 0x78) == 0);
            CHECK(get<uint64_t>(result.image, loadConfig + 0x80) == fixture.preferredBase + 0x2800);
            CHECK(get<uint64_t>(result.image, loadConfig + 0x88) == 0);
            CHECK(get<uint32_t>(result.image, loadConfig + 0x90) == 0);
        }

        // Parse the rebuilt descriptors/ILT/IAT directly from their RVAs.
        const uint32_t importRva = disk.directoryRva(1);
        const size_t descriptors = disk.rvaToOffset(importRva);
        CHECK(descriptors != static_cast<size_t>(-1));
        if (descriptors != static_cast<size_t>(-1)) {
            const uint32_t intactIlt = get<uint32_t>(result.image, descriptors + 0);
            const uint32_t intactName = get<uint32_t>(result.image, descriptors + 12);
            const uint32_t intactIat = get<uint32_t>(result.image, descriptors + 16);
            const uint32_t firstIlt = get<uint32_t>(result.image, descriptors + 20);
            const uint32_t firstName = get<uint32_t>(result.image, descriptors + 32);
            const uint32_t firstIat = get<uint32_t>(result.image, descriptors + 36);
            const uint32_t secondIlt = get<uint32_t>(result.image, descriptors + 40);
            const uint32_t secondName = get<uint32_t>(result.image, descriptors + 52);
            const uint32_t secondIat = get<uint32_t>(result.image, descriptors + 56);
            CHECK(disk.rvaString(intactName) == "KERNEL32.dll");
            CHECK(intactIlt == 0x2200);
            CHECK(intactIat == 0x2220);
            CHECK(disk.rvaString(firstName) == "KERNEL32.dll");
            CHECK(disk.rvaString(secondName) == "USER32.dll");
            CHECK(firstIat == 0x4100);
            CHECK(secondIat == 0x4110);

            const size_t firstThunk = disk.rvaToOffset(firstIlt);
            const size_t secondThunk = disk.rvaToOffset(secondIlt);
            CHECK(firstThunk != static_cast<size_t>(-1));
            CHECK(secondThunk != static_cast<size_t>(-1));
            if (firstThunk != static_cast<size_t>(-1)) {
                const uint64_t named = get<uint64_t>(result.image, firstThunk);
                const uint64_t ordinal = get<uint64_t>(result.image, firstThunk + 8);
                CHECK((named & 0x8000000000000000ull) == 0);
                CHECK(disk.rvaString(static_cast<uint32_t>(named) + 2) == "GetProcAddress");
                CHECK(ordinal == (0x8000000000000000ull | 7ull));
                CHECK(get<uint64_t>(result.image, firstThunk + 16) == 0);
                const size_t rebuiltIat = disk.rvaToOffset(firstIat);
                CHECK(rebuiltIat != static_cast<size_t>(-1));
                if (rebuiltIat != static_cast<size_t>(-1)) {
                    CHECK(get<uint64_t>(result.image, rebuiltIat) == named);
                    CHECK(get<uint64_t>(result.image, rebuiltIat + 8) == ordinal);
                }
            }
            if (secondThunk != static_cast<size_t>(-1)) {
                const uint64_t named = get<uint64_t>(result.image, secondThunk);
                CHECK(disk.rvaString(static_cast<uint32_t>(named) + 2) == "MessageBoxA");
                CHECK(get<uint64_t>(result.image, secondThunk + 8) == 0);
            }
        }

        const size_t dsimp = disk.section(".dsimp");
        CHECK(dsimp != static_cast<size_t>(-1));
        if (dsimp != static_cast<size_t>(-1))
            CHECK(get<uint32_t>(result.image, dsimp + 36) == 0xc0000040u);
    }

    // Reconstruction is deterministic down to diagnostics, and never mutates input.
    {
        const PeUnpackResult again = RebuildMappedPe(fixture.mapped, options);
        CHECK(again.success);
        CHECK(again.image == result.image);
        CHECK(again.report == result.report);
        CHECK(again.issues.size() == result.issues.size());
        CHECK(fixture.mapped == pristine);
    }

    // A malformed relocation table is transactional: an early valid block may
    // not leave a half-normalized image when the runtime-base fallback is chosen.
    {
        Fixture malformed = buildMappedPe64();
        setDirectory(malformed, 5, 0x3000, 20);
        put<uint32_t>(malformed.mapped, 0x300c, 0x2000);
        put<uint32_t>(malformed.mapped, 0x3010, 7); // invalid block size after valid block
        PeUnpackOptions fallback;
        fallback.runtimeImageBase = malformed.runtimeBase;
        fallback.rebuildObservedImports = false;
        const auto rebuilt = RebuildMappedPe(malformed.mapped, fallback);
        CHECK(rebuilt.success);
        CHECK(rebuilt.outputImageBase == malformed.runtimeBase);
        CHECK(rebuilt.repairs.relocationEntriesNormalized == 0);
        CHECK(hasIssue(rebuilt, "relocs-malformed"));
        if (rebuilt.success) {
            const DiskPe disk(rebuilt.image);
            const size_t pointer = disk.rvaToOffset(0x1100);
            CHECK(pointer != static_cast<size_t>(-1));
            if (pointer != static_cast<size_t>(-1))
                CHECK(get<uint64_t>(rebuilt.image, pointer) == malformed.runtimeBase + 0x1234);
            CHECK(get<uint64_t>(rebuilt.image, disk.opt + 24) == malformed.runtimeBase);
            CHECK((get<uint16_t>(rebuilt.image, disk.opt + 70) & 0x40u) == 0);
        }
    }

    // Descriptor walking is bounded by the import directory's declared size.
    // A valid-looking descriptor immediately after that range must never cause
    // its IAT to be rewritten.
    {
        Fixture bounded = buildMappedPe64();
        setDirectory(bounded, 1, 0x2100, 20); // exactly one descriptor
        put<uint32_t>(bounded.mapped, 0x2114 + 0, 0x2260);
        put<uint32_t>(bounded.mapped, 0x2114 + 12, 0x2180);
        put<uint32_t>(bounded.mapped, 0x2114 + 16, 0x2240);
        put<uint64_t>(bounded.mapped, 0x2260, 0x2250);
        put<uint64_t>(bounded.mapped, 0x2268, 0);
        put<uint64_t>(bounded.mapped, 0x2240, 0x7fff88888888ull);
        put<uint64_t>(bounded.mapped, 0x2248, 0);
        PeUnpackOptions opts;
        opts.runtimeImageBase = bounded.runtimeBase;
        opts.rebuildObservedImports = false;
        const auto rebuilt = RebuildMappedPe(bounded.mapped, opts);
        CHECK(rebuilt.success);
        CHECK(rebuilt.repairs.importSlotsRestored == 1);
        if (rebuilt.success) {
            const DiskPe disk(rebuilt.image);
            const size_t firstIat = disk.rvaToOffset(0x2220);
            const size_t outsideIat = disk.rvaToOffset(0x2240);
            CHECK(firstIat != static_cast<size_t>(-1));
            CHECK(outsideIat != static_cast<size_t>(-1));
            if (firstIat != static_cast<size_t>(-1))
                CHECK(get<uint64_t>(rebuilt.image, firstIat) == 0x2250);
            if (outsideIat != static_cast<size_t>(-1))
                CHECK(get<uint64_t>(rebuilt.image, outsideIat) == 0x7fff88888888ull);
            CHECK(disk.directoryRva(11) == 0 && disk.directorySize(11) == 0);
        }
    }

    // ILT restoration is all-or-nothing: an unterminated source or a
    // destination whose terminating slot is not section-backed leaves the IAT
    // byte-identical.
    {
        Fixture unterminated = buildMappedPe64();
        put<uint32_t>(unterminated.mapped, 0x2100, 0x4ff8);
        put<uint64_t>(unterminated.mapped, 0x4ff8, 0x2250);
        PeUnpackOptions opts;
        opts.runtimeImageBase = unterminated.runtimeBase;
        opts.rebuildObservedImports = false;
        const auto rebuilt = RebuildMappedPe(unterminated.mapped, opts);
        CHECK(rebuilt.success);
        CHECK(rebuilt.repairs.importSlotsRestored == 0);
        if (rebuilt.success) {
            const DiskPe disk(rebuilt.image);
            const size_t iat = disk.rvaToOffset(0x2220);
            CHECK(iat != static_cast<size_t>(-1));
            if (iat != static_cast<size_t>(-1))
                CHECK(get<uint64_t>(rebuilt.image, iat) == 0x7fff12345678ull);
        }

        Fixture shortDestination = buildMappedPe64();
        put<uint32_t>(shortDestination.mapped, 0x2100 + 16, 0x41f8);
        put<uint64_t>(shortDestination.mapped, 0x41f8, 0x7fff99999999ull);
        opts.runtimeImageBase = shortDestination.runtimeBase;
        const auto shortRebuilt = RebuildMappedPe(shortDestination.mapped, opts);
        CHECK(shortRebuilt.success);
        CHECK(shortRebuilt.repairs.importSlotsRestored == 0);
        if (shortRebuilt.success) {
            const DiskPe disk(shortRebuilt.image);
            const size_t iat = disk.rvaToOffset(0x41f8);
            CHECK(iat != static_cast<size_t>(-1));
            if (iat != static_cast<size_t>(-1))
                CHECK(get<uint64_t>(shortRebuilt.image, iat) == 0x7fff99999999ull);
        }
    }

    // A partial relocation-directory tail is malformed, even after a complete
    // valid block, and therefore selects the transactional runtime-base path.
    {
        Fixture trailing = buildMappedPe64();
        setDirectory(trailing, 5, 0x3000, 13);
        PeUnpackOptions opts;
        opts.runtimeImageBase = trailing.runtimeBase;
        opts.rebuildObservedImports = false;
        const auto rebuilt = RebuildMappedPe(trailing.mapped, opts);
        CHECK(rebuilt.success);
        CHECK(rebuilt.outputImageBase == trailing.runtimeBase);
        CHECK(rebuilt.repairs.relocationEntriesNormalized == 0);
        CHECK(hasIssue(rebuilt, "relocs-malformed"));
    }

    // A low NumberOfRvaAndSizes does not make the writer scribble over the
    // section table: the physically present import slot is enabled explicitly.
    {
        Fixture lowDirs = buildMappedPe64();
        put<uint32_t>(lowDirs.mapped, lowDirs.opt + 108, 1);
        PeUnpackOptions low = options;
        const auto rebuilt = RebuildMappedPe(lowDirs.mapped, low);
        CHECK(rebuilt.success);
        if (rebuilt.success) {
            const DiskPe disk(rebuilt.image);
            CHECK(get<uint32_t>(rebuilt.image, disk.opt + 108) == 13);
            CHECK(disk.directoryRva(1) != 0 && disk.directorySize(1) == 80);
            CHECK(disk.directoryRva(12) == 0x2220 && disk.directorySize(12) == 0x1f00);
            CHECK(disk.sectionCount == 5);
            CHECK(disk.section(".text") != static_cast<size_t>(-1));
            CHECK(disk.section(".dsimp") != static_cast<size_t>(-1));
        }
    }

    // A hostile directory count is clamped to the optional-header capacity and
    // the repaired value is persisted into the output header.
    {
        Fixture tooManyDirs = buildMappedPe64();
        put<uint32_t>(tooManyDirs.mapped, tooManyDirs.opt + 108, 99);
        PeUnpackOptions opts;
        opts.runtimeImageBase = tooManyDirs.runtimeBase;
        opts.rebuildObservedImports = false;
        const auto rebuilt = RebuildMappedPe(tooManyDirs.mapped, opts);
        CHECK(rebuilt.success);
        CHECK(hasIssue(rebuilt, "directory-count"));
        if (rebuilt.success) {
            const DiskPe disk(rebuilt.image);
            CHECK(get<uint32_t>(rebuilt.image, disk.opt + 108) == 16);
        }
    }

    // Clearing a structurally invalid load-config directory also clears the
    // image-level Guard CF promise.
    {
        Fixture invalidLoadConfig = buildMappedPe64();
        setDirectory(invalidLoadConfig, 10, 0x2400, 4);
        put<uint32_t>(invalidLoadConfig.mapped, 0x2400, 4);
        PeUnpackOptions opts;
        opts.runtimeImageBase = invalidLoadConfig.runtimeBase;
        opts.rebuildObservedImports = false;
        const auto rebuilt = RebuildMappedPe(invalidLoadConfig.mapped, opts);
        CHECK(rebuilt.success);
        CHECK(hasIssue(rebuilt, "load-config-invalid"));
        if (rebuilt.success) {
            const DiskPe disk(rebuilt.image);
            CHECK(disk.directoryRva(10) == 0 && disk.directorySize(10) == 0);
            CHECK((get<uint16_t>(rebuilt.image, disk.opt + 70) & 0x4000u) == 0);
        }
    }

    // Existing entry points receive the same strict captured-section check as
    // analyst-selected OEPs, and malformed section layouts fail atomically.
    {
        Fixture entryHole = buildMappedPe64();
        put<uint32_t>(entryHole.mapped, entryHole.opt + 16, 0x3800);
        PeUnpackOptions opts;
        opts.runtimeImageBase = entryHole.runtimeBase;
        const auto failedEntry = RebuildMappedPe(entryHole.mapped, opts);
        CHECK(!failedEntry.success);
        CHECK(hasIssue(failedEntry, "entry-section"));
        CHECK(failedEntry.rawMappedImage == entryHole.mapped);

        Fixture overlap = buildMappedPe64();
        put<uint32_t>(overlap.mapped, overlap.sectionTable + 40 + 12, 0x1000);
        const auto failedOverlap = RebuildMappedPe(overlap.mapped, opts);
        CHECK(!failedOverlap.success);
        CHECK(hasIssue(failedOverlap, "section-overlap"));

        Fixture badAlignment = buildMappedPe64();
        put<uint32_t>(badAlignment.mapped, badAlignment.opt + 36, 0x100);
        const auto failedAlignment = RebuildMappedPe(badAlignment.mapped, opts);
        CHECK(!failedAlignment.success);
        CHECK(hasIssue(failedAlignment, "alignment"));
    }

    // OEP bounds are strict and failure still returns the captured mapping.
    {
        PeUnpackOptions badOep;
        badOep.runtimeImageBase = fixture.runtimeBase;
        badOep.hasOep = true;
        badOep.oepVA = fixture.runtimeBase + 0x5000;
        const auto failed = RebuildMappedPe(fixture.mapped, badOep);
        CHECK(!failed.success);
        CHECK(failed.image.empty());
        CHECK(failed.rawMappedImage == fixture.mapped);
        CHECK(failed.repairs.failureArtifactOnly);
        CHECK(hasIssue(failed, "oep-range"));
        CHECK(failed.report.find("failure artifact only") != std::string::npos);
    }

    // Structurally hostile captures fail atomically with bounded diagnostics and
    // preserve the raw bytes for an analyst-directed failure dump.
    {
        std::vector<uint8_t> malformed(0x80, 0);
        put<uint16_t>(malformed, 0, 0x5a4d);
        put<uint32_t>(malformed, 0x3c, 0xfffffff0u);
        PeUnpackOptions opts;
        opts.runtimeImageBase = fixture.runtimeBase;
        const auto failed = RebuildMappedPe(malformed, opts);
        CHECK(!failed.success);
        CHECK(failed.image.empty());
        CHECK(failed.rawMappedImage == malformed);
        CHECK(failed.repairs.failureArtifactOnly);
        CHECK(hasIssue(failed, "bad-pe-offset"));
        CHECK(failed.issues.size() <= 256);
        CHECK(failed.report.find("failure artifact only") != std::string::npos);
    }

    if (g_failures == 0)
        std::printf("pe_unpack_test: all checks passed\n");
    else
        std::printf("pe_unpack_test: %d check(s) failed\n", g_failures);
    return g_failures ? 1 : 0;
}
