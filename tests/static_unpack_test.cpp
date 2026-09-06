#include "Core/StaticUnpack.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

using namespace ds;

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); ++failures; } } while (0)

template <typename T>
static void put(std::vector<uint8_t>& bytes, size_t offset, T value) {
    if (offset + sizeof(T) > bytes.size()) bytes.resize(offset + sizeof(T));
    std::memcpy(bytes.data() + offset, &value, sizeof(T));
}

template <typename T>
static T get(const std::vector<uint8_t>& bytes, size_t offset) {
    T value{};
    if (offset + sizeof(T) <= bytes.size()) std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

static constexpr uint8_t kLzmaProps[5] = { 0x5d, 0x00, 0x10, 0x00, 0x00 };
static constexpr uint8_t kCompressed[19] = {
    0x00, 0x24, 0x0c, 0x54, 0x0c, 0x34, 0x8a, 0x1a, 0x77, 0xeb,
    0x48, 0x22, 0xdf, 0xff, 0xff, 0xdd, 0x02, 0x00, 0x00
};
static constexpr uint8_t kPhraseCompressed[76] = {
    0x00, 0x2a, 0x1a, 0x08, 0xa2, 0x03, 0x25, 0x66, 0xf1, 0x4b,
    0x78, 0xc5, 0xa2, 0x05, 0xff, 0x2e, 0xe6, 0xd9, 0xd2, 0x20,
    0x1a, 0xad, 0x34, 0xf8, 0xe2, 0x1d, 0xe8, 0x41, 0x36, 0xfa,
    0xdc, 0x06, 0x69, 0xbb, 0x3c, 0xe4, 0x10, 0x34, 0x27, 0x09,
    0xeb, 0xb3, 0x66, 0xe3, 0xec, 0x99, 0x39, 0x7e, 0x50, 0x5b,
    0xe5, 0x27, 0x85, 0x08, 0x38, 0xa1, 0x3d, 0x9a, 0x3c, 0x41,
    0xc4, 0x18, 0x4a, 0x53, 0xf6, 0x6a, 0x8a, 0xbf, 0xc0, 0xd6,
    0x9f, 0xff, 0x30, 0x02, 0x00, 0x00
};

// Raw LZMA1 stream for a complete 0x600-byte PE whose unchanged entry lies in
// .vmp1. Structural PE validity must not be promoted to unpacked-OEP trust.
static constexpr uint8_t kNestedPackedPeCompressed[107] = {
    0x00, 0x26, 0x96, 0x7c, 0x1b, 0x8c, 0xbb, 0x18, 0x1b, 0x8c, 0x36, 0xce, 0xda, 0xba, 0x3f, 0x17,
    0x4e, 0x3c, 0x4b, 0x29, 0xad, 0x8b, 0x0c, 0xd5, 0x06, 0x3b, 0x9c, 0xa6, 0xa2, 0x4b, 0x05, 0xb6,
    0x35, 0xca, 0x33, 0xc2, 0xd6, 0x65, 0x1c, 0x73, 0xbb, 0xc4, 0x08, 0xc7, 0xfa, 0x03, 0x1a, 0x43,
    0x7c, 0x8f, 0xbf, 0x96, 0x5d, 0xe9, 0x42, 0x83, 0x1f, 0x38, 0xf0, 0x0f, 0x82, 0xfc, 0xd6, 0xbf,
    0xf6, 0x16, 0x1b, 0x10, 0x08, 0xa3, 0xe5, 0xbf, 0x37, 0x94, 0x84, 0x11, 0x92, 0x97, 0x15, 0x87,
    0x4c, 0x70, 0x5b, 0xe3, 0x59, 0x7f, 0xf0, 0x25, 0x83, 0xd7, 0x1b, 0x36, 0xba, 0x39, 0x29, 0x30,
    0x05, 0x54, 0x71, 0x41, 0x18, 0xff, 0xff, 0xfb, 0x99, 0x2a, 0xa0
};

// The compressed payload is 512 bytes: 48 31 C0 C3 followed by 508 NOPs.
static std::vector<uint8_t> payload() {
    std::vector<uint8_t> result(512, 0x90);
    result[0] = 0x48; result[1] = 0x31; result[2] = 0xc0; result[3] = 0xc3;
    return result;
}

struct Fixture {
    std::vector<uint8_t> bytes;
    size_t sectionTable = 0;
};

static Fixture basePe(size_t rawSize = 0x400) {
    Fixture f;
    f.bytes.assign(0x200 + rawSize, 0);
    put<uint16_t>(f.bytes, 0, 0x5a4d);
    put<uint32_t>(f.bytes, 0x3c, 0x80);
    put<uint32_t>(f.bytes, 0x80, 0x00004550);
    put<uint16_t>(f.bytes, 0x84, 0x8664);
    put<uint16_t>(f.bytes, 0x86, 2);
    put<uint16_t>(f.bytes, 0x94, 0x00f0);
    put<uint16_t>(f.bytes, 0x96, 0x0022);
    const size_t opt = 0x98;
    put<uint16_t>(f.bytes, opt, 0x20b);
    put<uint32_t>(f.bytes, opt + 16, 0x1000);
    put<uint64_t>(f.bytes, opt + 24, 0x140000000ull);
    put<uint32_t>(f.bytes, opt + 32, 0x1000);
    put<uint32_t>(f.bytes, opt + 36, 0x200);
    put<uint16_t>(f.bytes, opt + 40, 6);
    put<uint16_t>(f.bytes, opt + 48, 6);
    put<uint32_t>(f.bytes, opt + 56, 0x3000);
    put<uint32_t>(f.bytes, opt + 60, 0x200);
    put<uint16_t>(f.bytes, opt + 68, 3);
    put<uint16_t>(f.bytes, opt + 70, 0x8160);
    put<uint64_t>(f.bytes, opt + 72, 0x100000);
    put<uint64_t>(f.bytes, opt + 80, 0x1000);
    put<uint64_t>(f.bytes, opt + 88, 0x100000);
    put<uint64_t>(f.bytes, opt + 96, 0x1000);
    put<uint32_t>(f.bytes, opt + 108, 16);

    f.sectionTable = opt + 0xf0;
    std::memcpy(f.bytes.data() + f.sectionTable, ".text", 5);
    put<uint32_t>(f.bytes, f.sectionTable + 8, 0x1000);
    put<uint32_t>(f.bytes, f.sectionTable + 12, 0x1000);
    put<uint32_t>(f.bytes, f.sectionTable + 16, 0);
    put<uint32_t>(f.bytes, f.sectionTable + 20, 0);
    put<uint32_t>(f.bytes, f.sectionTable + 36, 0x60000020);

    const size_t vmp = f.sectionTable + 40;
    std::memcpy(f.bytes.data() + vmp, ".vmp1", 5);
    put<uint32_t>(f.bytes, vmp + 8, 0x1000);
    put<uint32_t>(f.bytes, vmp + 12, 0x2000);
    put<uint32_t>(f.bytes, vmp + 16, static_cast<uint32_t>(rawSize));
    put<uint32_t>(f.bytes, vmp + 20, 0x200);
    put<uint32_t>(f.bytes, vmp + 36, 0xe0000040);
    return f;
}

static Fixture basePe32(size_t rawSize = 0x400) {
    Fixture f;
    f.bytes.assign(0x200 + rawSize, 0);
    put<uint16_t>(f.bytes, 0, 0x5a4d);
    put<uint32_t>(f.bytes, 0x3c, 0x80);
    put<uint32_t>(f.bytes, 0x80, 0x00004550);
    put<uint16_t>(f.bytes, 0x84, 0x014c);
    put<uint16_t>(f.bytes, 0x86, 2);
    put<uint16_t>(f.bytes, 0x94, 0x00e0);
    put<uint16_t>(f.bytes, 0x96, 0x0102);
    const size_t opt = 0x98;
    put<uint16_t>(f.bytes, opt, 0x10b);
    put<uint32_t>(f.bytes, opt + 16, 0x1000);
    put<uint32_t>(f.bytes, opt + 28, 0x00400000);
    put<uint32_t>(f.bytes, opt + 32, 0x1000);
    put<uint32_t>(f.bytes, opt + 36, 0x200);
    put<uint16_t>(f.bytes, opt + 40, 6);
    put<uint16_t>(f.bytes, opt + 48, 6);
    put<uint32_t>(f.bytes, opt + 56, 0x3000);
    put<uint32_t>(f.bytes, opt + 60, 0x200);
    put<uint16_t>(f.bytes, opt + 68, 3);
    put<uint16_t>(f.bytes, opt + 70, 0x8140);
    put<uint32_t>(f.bytes, opt + 72, 0x100000);
    put<uint32_t>(f.bytes, opt + 76, 0x1000);
    put<uint32_t>(f.bytes, opt + 80, 0x100000);
    put<uint32_t>(f.bytes, opt + 84, 0x1000);
    put<uint32_t>(f.bytes, opt + 92, 16);

    f.sectionTable = opt + 0xe0;
    std::memcpy(f.bytes.data() + f.sectionTable, ".text", 5);
    put<uint32_t>(f.bytes, f.sectionTable + 8, 0x1000);
    put<uint32_t>(f.bytes, f.sectionTable + 12, 0x1000);
    put<uint32_t>(f.bytes, f.sectionTable + 36, 0x60000020);
    const size_t vmp = f.sectionTable + 40;
    std::memcpy(f.bytes.data() + vmp, ".vmp1", 5);
    put<uint32_t>(f.bytes, vmp + 8, 0x1000);
    put<uint32_t>(f.bytes, vmp + 12, 0x2000);
    put<uint32_t>(f.bytes, vmp + 16, static_cast<uint32_t>(rawSize));
    put<uint32_t>(f.bytes, vmp + 20, 0x200);
    put<uint32_t>(f.bytes, vmp + 36, 0xe0000040);
    return f;
}

static Fixture packerInfoFixture() {
    Fixture f = basePe();
    // PACKER_INFO[0] = shared LZMA props, [1] = block SrcRVA -> DstRVA.
    put<uint32_t>(f.bytes, 0x220, 0x2040);
    put<uint32_t>(f.bytes, 0x224, 5);
    put<uint32_t>(f.bytes, 0x228, 0x2050);
    put<uint32_t>(f.bytes, 0x22c, 0x1000);
    std::memcpy(f.bytes.data() + 0x240, kLzmaProps, sizeof(kLzmaProps));
    std::memcpy(f.bytes.data() + 0x250, kCompressed, sizeof(kCompressed));
    return f;
}

static Fixture packerInfo32Fixture() {
    Fixture f = basePe32();
    put<uint32_t>(f.bytes, 0x220, 0x2040);
    put<uint32_t>(f.bytes, 0x224, 5);
    put<uint32_t>(f.bytes, 0x228, 0x2050);
    put<uint32_t>(f.bytes, 0x22c, 0x1000);
    std::memcpy(f.bytes.data() + 0x240, kLzmaProps, sizeof(kLzmaProps));
    std::memcpy(f.bytes.data() + 0x250, kCompressed, sizeof(kCompressed));
    return f;
}

static Fixture lzmaAloneFixture() {
    Fixture f = basePe();
    std::memcpy(f.bytes.data() + 0x220, kLzmaProps, sizeof(kLzmaProps));
    put<uint64_t>(f.bytes, 0x225, 512);
    std::memcpy(f.bytes.data() + 0x22d, kCompressed, sizeof(kCompressed));
    return f;
}

static Fixture nestedPackedPeFixture() {
    Fixture f = basePe();
    std::memcpy(f.bytes.data() + 0x220, kLzmaProps, sizeof(kLzmaProps));
    put<uint64_t>(f.bytes, 0x225, 0x600);
    std::memcpy(f.bytes.data() + 0x22d, kNestedPackedPeCompressed,
                sizeof(kNestedPackedPeCompressed));
    return f;
}

static Fixture storedFixture() {
    Fixture f = basePe(0x1000);
    const auto plain = payload();
    std::copy(plain.begin(), plain.end(), f.bytes.begin() + 0x200);
    std::fill(f.bytes.begin() + 0x200 + plain.size(), f.bytes.begin() + 0x1200,
              static_cast<uint8_t>(0xcc));
    // Invalid properties descriptor in the overlay, followed by the exact
    // Src/Dst table.  The source section extent is exactly the target extent.
    f.bytes.resize(0x1210, 0);
    put<uint32_t>(f.bytes, 0x1200, 0);
    put<uint32_t>(f.bytes, 0x1204, 0);
    put<uint32_t>(f.bytes, 0x1208, 0x2000);
    put<uint32_t>(f.bytes, 0x120c, 0x1000);
    return f;
}

static size_t diskRva(const std::vector<uint8_t>& image, uint32_t rva) {
    const uint32_t nt = get<uint32_t>(image, 0x3c);
    const uint16_t sections = get<uint16_t>(image, nt + 6);
    const uint16_t optional = get<uint16_t>(image, nt + 20);
    const size_t table = nt + 24 + optional;
    const uint32_t headers = get<uint32_t>(image, nt + 24 + 60);
    if (rva < headers) return rva;
    for (uint16_t i = 0; i < sections; ++i) {
        const size_t sh = table + static_cast<size_t>(i) * 40;
        const uint32_t va = get<uint32_t>(image, sh + 12);
        const uint32_t rawSize = get<uint32_t>(image, sh + 16);
        const uint32_t raw = get<uint32_t>(image, sh + 20);
        if (rva >= va && rva - va < rawSize) return raw + (rva - va);
    }
    return static_cast<size_t>(-1);
}

static bool issue(const StaticUnpackResult& result, const char* code) {
    for (const auto& item : result.issues) if (item.code == code) return true;
    return false;
}

static bool probeIssue(const StaticUnpackProbe& probe, const char* code) {
    for (const auto& item : probe.issues) if (item.code == code) return true;
    return false;
}

static uint64_t sourceHash(const std::vector<uint8_t>& bytes) {
    uint64_t hash = 1469598103934665603ull;
    for (uint8_t value : bytes) { hash ^= value; hash *= 1099511628211ull; }
    hash ^= bytes.size(); hash *= 1099511628211ull;
    return hash;
}

int main() {
    const Fixture packed = packerInfoFixture();
    const auto expected = payload();

    {
        const auto probe = ProbeStaticPackedPe(packed.bytes);
        CHECK(probe.recognized);
        CHECK(probe.likelyVmProtect);
        CHECK(probe.recommended == StaticUnpackStrategy::VmprotectPackerInfo);
        CHECK(probe.confidence >= 0.90f);
        CHECK(probe.blocks.size() == 1);
        if (!probe.blocks.empty()) {
            CHECK(probe.blocks[0].sourceRVA == 0x2050);
            CHECK(probe.blocks[0].sourceOffset == 0x250);
            CHECK(probe.blocks[0].destinationRVA == 0x1000);
            CHECK(probe.blocks[0].outputLimit == 0x1000);
            CHECK(probe.blocks[0].compressedSize > sizeof(kCompressed));
            CHECK(probe.blocks[0].compressedSize < packed.bytes.size());
            CHECK(probe.blocks[0].hasLzmaProperties);
        }
    }

    const auto unpacked = StaticUnpackPe(packed.bytes);
    CHECK(unpacked.success);
    CHECK(unpacked.decoded);
    CHECK(unpacked.diskImageReady);
    CHECK(unpacked.oepTrusted);
    CHECK(unpacked.entryRVA == 0x1000);
    CHECK(!unpacked.cancelled);
    CHECK(unpacked.strategy == StaticUnpackStrategy::VmprotectPackerInfo);
    CHECK(unpacked.blocks.size() == 1);
    CHECK(unpacked.blocks[0].complete);
    CHECK(unpacked.blocks[0].outputSize == expected.size());
    CHECK(unpacked.mappedImage.size() == 0x3000);
    CHECK(std::equal(expected.begin(), expected.end(), unpacked.mappedImage.begin() + 0x1000));
    CHECK(!unpacked.image.empty());
    const size_t text = diskRva(unpacked.image, 0x1000);
    CHECK(text != static_cast<size_t>(-1));
    if (text != static_cast<size_t>(-1))
        CHECK(std::equal(expected.begin(), expected.end(), unpacked.image.begin() + text));
    CHECK(unpacked.report.find("PACKER_INFO") != std::string::npos);
    CHECK(unpacked.report.find("Input consumed") != std::string::npos);
    CHECK(unpacked.report.find("OEP trust: trusted") != std::string::npos);

    // The descriptor/container path is bitness-neutral and the final handoff
    // reconstructs PE32 as well as PE32+.
    {
        const Fixture packed32 = packerInfo32Fixture();
        const auto result = StaticUnpackPe(packed32.bytes);
        CHECK(result.success);
        CHECK(result.diskImageReady);
        CHECK(result.mappedImage.size() == 0x3000);
        CHECK(std::equal(expected.begin(), expected.end(), result.mappedImage.begin() + 0x1000));
        const uint32_t nt = get<uint32_t>(result.image, 0x3c);
        CHECK(get<uint16_t>(result.image, nt + 24) == 0x10b);
    }

    // Deterministic reconstruction and diagnostics.
    {
        const auto again = StaticUnpackPe(packed.bytes);
        CHECK(again.success);
        CHECK(again.image == unpacked.image);
        CHECK(again.report == unpacked.report);
    }

    // The conservative fallback accepts a finite LZMA-alone header only inside
    // the VMP section and uses its declared size as an exact output bound.
    {
        const Fixture alone = lzmaAloneFixture();
        const auto probe = ProbeStaticPackedPe(alone.bytes);
        CHECK(probe.recognized);
        CHECK(probe.recommended == StaticUnpackStrategy::EmbeddedLzmaAlone);
        CHECK(probe.blocks.size() == 1);
        const auto result = StaticUnpackPe(alone.bytes);
        CHECK(result.success);
        CHECK(result.strategy == StaticUnpackStrategy::EmbeddedLzmaAlone);
        CHECK(result.blocks[0].outputSize == 512);
        CHECK(std::equal(expected.begin(), expected.end(), result.mappedImage.begin() + 0x1000));

        Fixture many = alone;
        std::memcpy(many.bytes.data() + 0x280, kLzmaProps, sizeof(kLzmaProps));
        put<uint64_t>(many.bytes, 0x285, 512);
        many.bytes[0x28d] = 0;
        StaticUnpackOptions bounded;
        bounded.maxLzmaCandidates = 1;
        const auto boundedProbe = ProbeStaticPackedPe(many.bytes, bounded);
        CHECK(boundedProbe.recognized);
        CHECK(probeIssue(boundedProbe, "lzma-candidate-cap"));
    }

    // Exact finite source/destination extents provide a separately-labelled
    // stored/raw strategy; a larger ambiguous source is never copied by prefix.
    {
        const Fixture stored = storedFixture();
        const auto probe = ProbeStaticPackedPe(stored.bytes);
        CHECK(probe.recognized);
        CHECK(probe.recommended == StaticUnpackStrategy::VmprotectPackerInfo);
        CHECK(!probe.blocks.empty() && probe.blocks[0].codec == StaticUnpackCodec::Stored);
        const auto result = StaticUnpackPe(stored.bytes);
        CHECK(result.success);
        CHECK(result.blocks[0].complete);
        CHECK(result.blocks[0].outputSize == 0x1000);
        CHECK(std::equal(expected.begin(), expected.end(), result.mappedImage.begin() + 0x1000));
    }

    // Manual stored blocks use the same transactional validator and cannot
    // overlap or silently truncate.
    {
        StaticUnpackOptions options;
        options.strategy = StaticUnpackStrategy::ManualBlocks;
        StaticUnpackBlock block;
        block.sourceOffset = 0x250;
        block.destinationRVA = 0x1000;
        block.compressedSize = 16;
        block.outputLimit = 16;
        block.codec = StaticUnpackCodec::Stored;
        options.manualBlocks.push_back(block);
        const auto result = StaticUnpackPe(packed.bytes, options);
        CHECK(result.success);
        CHECK(result.blocks[0].outputSize == 16);

        options.manualBlocks.push_back(block);
        const auto overlap = StaticUnpackPe(packed.bytes, options);
        CHECK(!overlap.success);
        CHECK(issue(overlap, "manual-block-overlap"));
    }

    // A second independent raw-LZMA vector exercises non-trivial literal and
    // long-distance match paths (80 repeated English phrases), not merely the
    // distance-one run used by the PACKER_INFO fixture.
    {
        Fixture phrase = basePe();
        std::memcpy(phrase.bytes.data() + 0x300, kPhraseCompressed, sizeof(kPhraseCompressed));
        StaticUnpackOptions options;
        options.strategy = StaticUnpackStrategy::ManualBlocks;
        options.rebuildDiskPe = false;
        StaticUnpackBlock block;
        block.sourceOffset = 0x300;
        block.destinationRVA = 0x1000;
        block.compressedSize = sizeof(kPhraseCompressed);
        block.outputLimit = 0x1000;
        block.codec = StaticUnpackCodec::Lzma1;
        block.hasLzmaProperties = true;
        std::copy(std::begin(kLzmaProps), std::end(kLzmaProps), block.lzmaProperties.begin());
        options.manualBlocks.push_back(block);
        const auto result = StaticUnpackPe(phrase.bytes, options);
        CHECK(result.success);
        CHECK(result.blocks[0].outputSize == 3600);
        const std::string sentence = "The quick brown fox jumps over the lazy dog.\n";
        for (size_t i = 0; i < 80; ++i)
            CHECK(std::memcmp(result.mappedImage.data() + 0x1000 + i * sentence.size(),
                              sentence.data(), sentence.size()) == 0);
    }

    // Truncated compressed ranges fail without exposing a partially modified
    // mapping, while preserving the original packed bytes as the raw artifact.
    {
        Fixture broken = packed;
        put<uint32_t>(broken.bytes, 0x228, 0x23ff);
        const auto result = StaticUnpackPe(broken.bytes);
        CHECK(!result.success);
        CHECK(!result.decoded);
        CHECK(result.mappedImage.empty());
        CHECK(result.rawArtifact == broken.bytes);
        CHECK(issue(result, "lzma-decode"));
    }

    // Automatic mode does not become trapped by a forged/stale descriptor
    // table: after its bounded decode fails, an independently valid container
    // candidate may win and the fallback is recorded explicitly.
    {
        Fixture mixed = packed;
        put<uint32_t>(mixed.bytes, 0x228, 0x23ff); // recognized table, invalid stream
        std::memcpy(mixed.bytes.data() + 0x300, kLzmaProps, sizeof(kLzmaProps));
        put<uint64_t>(mixed.bytes, 0x305, 512);
        std::memcpy(mixed.bytes.data() + 0x30d, kCompressed, sizeof(kCompressed));
        const auto result = StaticUnpackPe(mixed.bytes);
        CHECK(result.success);
        CHECK(result.strategy == StaticUnpackStrategy::EmbeddedLzmaAlone);
        CHECK(issue(result, "strategy-fallback"));
        CHECK(result.mappedImage.size() >= 0x1000 + expected.size());
        if (result.mappedImage.size() >= 0x1000 + expected.size())
            CHECK(std::equal(expected.begin(), expected.end(), result.mappedImage.begin() + 0x1000));
    }

    // A decoded mapping is still retained when the original packed header has
    // no valid entry-point owner and disk reconstruction therefore refuses to
    // claim a runnable PE.
    {
        Fixture badEntry = packed;
        put<uint32_t>(badEntry.bytes, 0x98 + 16, 0x3000);
        const auto result = StaticUnpackPe(badEntry.bytes);
        CHECK(!result.success);
        CHECK(result.decoded);
        CHECK(!result.diskImageReady);
        CHECK(result.mappedImage.size() == 0x3000);
        CHECK(result.rawArtifact.empty()); // mappedImage is the retained decoded failure artifact
        CHECK(issue(result, "pe-entry-range"));
        CHECK(issue(result, "pe-reconstruction"));
    }

    // Retaining an unchanged packer-loader entry is useful for analysis but is
    // not honestly labelled as a clean/runnable OEP. A validated analyst OEP
    // upgrades the same reconstruction to trusted.
    {
        Fixture loaderEntry = packed;
        put<uint32_t>(loaderEntry.bytes, 0x98 + 16, 0x2000); // .vmp1
        const auto unverified = StaticUnpackPe(loaderEntry.bytes);
        CHECK(unverified.success);
        CHECK(unverified.diskImageReady);
        CHECK(!unverified.oepTrusted);
        CHECK(unverified.entryRVA == 0x2000);
        CHECK(issue(unverified, "oep-unverified"));
        CHECK(unverified.report.find("OEP trust: UNVERIFIED") != std::string::npos);

        Fixture disguisedLoader = loaderEntry;
        std::memset(disguisedLoader.bytes.data() + disguisedLoader.sectionTable + 40, 0, 8);
        std::memcpy(disguisedLoader.bytes.data() + disguisedLoader.sectionTable + 40, ".text", 5);
        const auto disguised = StaticUnpackPe(disguisedLoader.bytes);
        CHECK(disguised.success);
        CHECK(!disguised.oepTrusted); // an executable/non-vmp name is not recovery evidence
        CHECK(issue(disguised, "oep-unverified"));

        StaticUnpackOptions manual;
        manual.runtimeImageBase = 0x140000000ull;
        manual.hasOep = true;
        manual.oepVA = manual.runtimeImageBase + 0x1000;
        manual.retainPackedSections = false;
        const auto trusted = StaticUnpackPe(loaderEntry.bytes, manual);
        CHECK(trusted.success);
        CHECK(trusted.oepTrusted);
        CHECK(trusted.entryRVA == 0x1000);
        CHECK(issue(trusted, "strip-unsupported"));
        CHECK(issue(trusted, "packer-sections-retained"));
    }

    // A complete decoded PE may itself still be packed. Its structurally valid
    // .vmp entry stays analysis-only unless the analyst supplies an executable
    // OEP, which is validated and written into the decoded optional header.
    {
        Fixture nested = nestedPackedPeFixture();
        const auto unverified = StaticUnpackPe(nested.bytes);
        CHECK(unverified.success);
        CHECK(unverified.diskImageReady);
        CHECK(unverified.entryRVA == 0x2000);
        CHECK(!unverified.oepTrusted);
        CHECK(issue(unverified, "oep-unverified"));

        // The outer packer's base deliberately differs from the nested PE.
        // Manual OEP interpretation must use the decoded PE's preferred base.
        put<uint64_t>(nested.bytes, 0x98 + 24, 0x180000000ull);
        StaticUnpackOptions manual;
        manual.runtimeImageBase = 0x180000000ull;
        manual.hasOep = true;
        manual.oepVA = 0x140000000ull + 0x1000;
        const auto trusted = StaticUnpackPe(nested.bytes, manual);
        CHECK(trusted.success);
        CHECK(trusted.diskImageReady);
        CHECK(trusted.oepTrusted);
        CHECK(trusted.entryRVA == 0x1000);
        CHECK(get<uint32_t>(trusted.image, 0x98 + 16) == 0x1000);
    }

    // Invalid caps and cancellation are explicit terminal outcomes.
    {
        StaticUnpackOptions tiny;
        tiny.maxOutputBytes = 0x2000;
        const auto refused = StaticUnpackPe(packed.bytes, tiny);
        CHECK(!refused.success);

        StaticUnpackOptions raised;
        raised.maxOutputBytes = 513ull * 1024ull * 1024ull;
        const auto hardCap = StaticUnpackPe(packed.bytes, raised);
        CHECK(!hardCap.success);
        CHECK(issue(hardCap, "invalid-caps"));

        StaticUnpackOptions noCandidates;
        noCandidates.maxLzmaCandidates = 0;
        const auto zeroCandidateCap = StaticUnpackPe(packed.bytes, noCandidates);
        CHECK(!zeroCandidateCap.success);
        CHECK(issue(zeroCandidateCap, "invalid-caps"));

        StaticUnpackOptions workspace;
        workspace.maxOutputBytes = 0x3000;
        const auto boundedWorkspace = StaticUnpackPe(packed.bytes, workspace);
        CHECK(!boundedWorkspace.success);
        CHECK(issue(boundedWorkspace, "workspace-cap"));

        const auto cancelled = StaticUnpackPe(packed.bytes, {}, [] { return true; });
        CHECK(cancelled.cancelled);
        CHECK(!cancelled.success);
    }

    // The one-job service owns the input, rejects concurrent work, and hands a
    // completed result back without the caller retaining a BinaryFile lifetime.
    {
        StaticUnpackService service;
        StaticUnpackRequest request;
        request.input = packed.bytes;
        CHECK(service.request(std::move(request)));
        StaticUnpackRequest second;
        second.input = packed.bytes;
        CHECK(!service.request(std::move(second)));
        StaticUnpackResult result;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!service.tryTakeResult(result) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        CHECK(result.success);
        CHECK(!service.pending());
        CHECK(service.progress().phase == StaticUnpackPhase::Complete);
        service.cancelAndWaitIdle();
        CHECK(service.progress().phase == StaticUnpackPhase::Idle);
    }

    // Path-backed requests defer all file I/O and bulk allocation to the worker,
    // while preserving the vector source for pure tests and existing callers.
    {
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        const std::filesystem::path path = std::filesystem::temp_directory_path() /
            ("ds_static_unpack_" + std::to_string(stamp) + ".bin");
        {
            std::ofstream output(path, std::ios::binary | std::ios::trunc);
            output.write(reinterpret_cast<const char*>(packed.bytes.data()),
                         static_cast<std::streamsize>(packed.bytes.size()));
            CHECK(static_cast<bool>(output));
        }
        StaticUnpackService service;
        StaticUnpackRequest request;
        const std::u8string utf8Path = path.u8string();
        request.inputPath.assign(reinterpret_cast<const char*>(utf8Path.data()), utf8Path.size());
        request.verifySourceIdentity = true;
        request.expectedSourceSize = packed.bytes.size();
        request.expectedSourceHash = sourceHash(packed.bytes);
        const std::string pathString = request.inputPath;
        CHECK(service.request(std::move(request)));
        StaticUnpackResult result;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!service.tryTakeResult(result) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        CHECK(result.success);
        CHECK(result.diskImageReady);

        StaticUnpackRequest ambiguous;
        ambiguous.input = packed.bytes;
        ambiguous.inputPath = "also-a-path";
        CHECK(!service.request(std::move(ambiguous)));

        StaticUnpackRequest changed;
        changed.inputPath = pathString;
        changed.verifySourceIdentity = true;
        changed.expectedSourceSize = packed.bytes.size();
        changed.expectedSourceHash = sourceHash(packed.bytes) ^ 1;
        CHECK(service.request(std::move(changed)));
        StaticUnpackResult changedResult;
        const auto changedDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (service.pending() && std::chrono::steady_clock::now() < changedDeadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        CHECK(service.tryTakeResult(changedResult));
        CHECK(!changedResult.success);
        CHECK(issue(changedResult, "input-identity"));
        CHECK(changedResult.rawArtifact.empty());

        std::error_code ec;
        std::filesystem::remove(path, ec);
        CHECK(!ec);

        StaticUnpackRequest missing;
        missing.inputPath = pathString + ".missing";
        CHECK(service.request(std::move(missing)));
        StaticUnpackResult missingResult;
        const auto missingDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (!service.tryTakeResult(missingResult) && std::chrono::steady_clock::now() < missingDeadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        CHECK(!missingResult.success);
        CHECK(issue(missingResult, "input-open"));
        CHECK(service.progress().phase == StaticUnpackPhase::Failed);
    }

    if (!failures) std::printf("static_unpack_test: all checks passed\n");
    else std::printf("static_unpack_test: %d check(s) failed\n", failures);
    return failures ? 1 : 0;
}
