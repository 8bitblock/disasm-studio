//
// firmware_sniffer_test.cpp
// Pure tests for raw BIOS/UEFI/PCI-ROM/Intel-descriptor recognition, reset
// mapping, x86 firmware jump recovery, architecture hints, bounded scanning,
// hostile declarations, and analysis landmarks.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\firmware_sniffer_test.cpp src\Core\FirmwareSniffer.cpp
//   .\firmware_sniffer_test.exe
//

#include "Core/FirmwareSniffer.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v);
    b[off + 1] = static_cast<uint8_t>(v >> 8);
}

static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) b[off + i] = static_cast<uint8_t>(v >> (i * 8));
}

static void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) b[off + i] = static_cast<uint8_t>(v >> (i * 8));
}

static uint16_t get16(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint16_t>(b[off]) |
           static_cast<uint16_t>(static_cast<uint16_t>(b[off + 1]) << 8);
}

static void fixChecksum8(std::vector<uint8_t>& b, size_t begin, size_t length) {
    b[begin + length - 1] = 0;
    uint8_t sum = 0;
    for (size_t i = 0; i + 1 < length; ++i)
        sum = static_cast<uint8_t>(sum + b[begin + i]);
    b[begin + length - 1] = static_cast<uint8_t>(0u - sum);
}

static void fixFvChecksum(std::vector<uint8_t>& b, size_t base, size_t headerLength) {
    put16(b, base + 0x32, 0);
    uint16_t sum = 0;
    for (size_t i = 0; i < headerLength; i += 2)
        sum = static_cast<uint16_t>(sum + get16(b, base + i));
    put16(b, base + 0x32, static_cast<uint16_t>(0u - sum));
}

static bool hasLandmark(const FirmwareDetection& d, const char* name, uint64_t offset) {
    return std::any_of(d.landmarks.begin(), d.landmarks.end(), [&](const FirmwareLandmark& l) {
        return l.name == name && l.location.valid && l.location.fileOffset == offset;
    });
}

static std::vector<uint8_t> makeFv(size_t totalSize, size_t base, size_t fvLength,
                                   bool withX64Pe = false) {
    std::vector<uint8_t> b(totalSize, 0);
    static const uint8_t ffs2[16] = {
        0x78,0xE5,0x8C,0x8C, 0x3D,0x8A, 0x1C,0x4F,
        0x99,0x35,0x89,0x61,0x85,0xC3,0x2D,0xD3
    };
    std::copy(ffs2, ffs2 + 16, b.begin() + static_cast<ptrdiff_t>(base + 0x10));
    put64(b, base + 0x20, fvLength);
    b[base + 0x28] = '_'; b[base + 0x29] = 'F';
    b[base + 0x2a] = 'V'; b[base + 0x2b] = 'H';
    put16(b, base + 0x30, 0x48);
    b[base + 0x36] = 0;
    b[base + 0x37] = 2;
    put32(b, base + 0x38, 1);
    put32(b, base + 0x3c, static_cast<uint32_t>(fvLength));
    put32(b, base + 0x40, 0);
    put32(b, base + 0x44, 0);
    fixFvChecksum(b, base, 0x48);

    if (withX64Pe) {
        const size_t image = base + 0x100;
        b[image] = 'M'; b[image + 1] = 'Z';
        put32(b, image + 0x3c, 0x40);
        b[image + 0x40] = 'P'; b[image + 0x41] = 'E';
        b[image + 0x42] = 0; b[image + 0x43] = 0;
        put16(b, image + 0x44, 0x8664);
    }
    return b;
}

static std::vector<uint8_t> makeLegacyOptionRom() {
    std::vector<uint8_t> b(1024, 0);
    b[0] = 0x55; b[1] = 0xaa; b[2] = 2;
    // Initialization entry: E9 rel16 to file offset 0x80.
    b[3] = 0xe9;
    put16(b, 4, static_cast<uint16_t>(0x80 - 6));
    put16(b, 0x18, 0x1c);
    b[0x1c] = 'P'; b[0x1d] = 'C'; b[0x1e] = 'I'; b[0x1f] = 'R';
    put16(b, 0x20, 0x1234); put16(b, 0x22, 0xabcd);
    put16(b, 0x26, 0x18);
    put16(b, 0x2c, 2);
    b[0x30] = 0x00;
    b[0x31] = 0x80;
    b[0x80] = 0x90;
    fixChecksum8(b, 0, b.size());
    return b;
}

static std::vector<uint8_t> makeEfiOptionRom() {
    std::vector<uint8_t> b(1024, 0);
    b[0] = 0x55; b[1] = 0xaa;
    put16(b, 2, 2);
    put32(b, 4, 0x00000ef1);
    put16(b, 8, 11);       // EFI boot-service subsystem
    put16(b, 0x0a, 0x8664);
    put16(b, 0x0c, 0);     // uncompressed
    put16(b, 0x16, 0x80);
    put16(b, 0x18, 0x1c);
    b[0x1c] = 'P'; b[0x1d] = 'C'; b[0x1e] = 'I'; b[0x1f] = 'R';
    put16(b, 0x20, 0x8086); put16(b, 0x22, 0x100e);
    put16(b, 0x26, 0x18);
    put16(b, 0x2c, 2);
    b[0x30] = 0x03;
    b[0x31] = 0x80;
    // Minimal bounded PE32+ image whose RVA 1000h entry maps to raw +200h.
    const size_t image = 0x80;
    b[image] = 'M'; b[image + 1] = 'Z';
    put32(b, image + 0x3c, 0x40);
    const size_t pe = image + 0x40;
    b[pe] = 'P'; b[pe + 1] = 'E';
    put16(b, pe + 4, 0x8664);
    put16(b, pe + 6, 1);
    put16(b, pe + 20, 0xf0);
    const size_t optional = pe + 24;
    put16(b, optional, 0x20b);
    put32(b, optional + 16, 0x1000);
    put32(b, optional + 60, 0x200);
    const size_t section = optional + 0xf0;
    b[section] = '.'; b[section + 1] = 't'; b[section + 2] = 'e'; b[section + 3] = 'x'; b[section + 4] = 't';
    put32(b, section + 8, 0x20);
    put32(b, section + 12, 0x1000);
    put32(b, section + 16, 0x20);
    put32(b, section + 20, 0x200);
    b[image + 0x200] = 0xc3;
    fixChecksum8(b, 0, b.size());
    return b;
}

int main() {
    // Empty and random raw data must not gain a firmware identity or mapping.
    CHECK(!SniffFirmware(nullptr, 0).detected());
    {
        std::vector<uint8_t> random(4096, 0x5a);
        FirmwareDetection d = SniffFirmware(random);
        CHECK(!d.detected());
        CHECK(!d.recommendedImageBaseValid);
        CHECK(!d.entry.detected);
        CHECK(d.architecture.mode == FirmwareCpuMode::Unknown);
    }
    // Adversarial byte-frequency cases remain ambiguous: repeated bytes can
    // resemble isolated Thumb PUSH halfwords but do not form framed functions.
    {
        std::vector<uint8_t> repeated(16 * 1024, 0xb5);
        FirmwareDetection d = SniffFirmware(repeated);
        CHECK(!d.detected());
        CHECK(d.architecture.mode == FirmwareCpuMode::Unknown);
    }
    {
        std::vector<uint8_t> randomLike(32 * 1024);
        uint32_t x = 0x71c3a59du;
        for (uint8_t& byte : randomLike) { x = x * 1664525u + 1013904223u; byte = (uint8_t)(x >> 24); }
        FirmwareDetection d = SniffFirmware(randomLike);
        if (d.architecture.mode != FirmwareCpuMode::Unknown)
            std::printf("random-like false hint: %s\n", d.architecture.evidence.c_str());
        CHECK(d.architecture.mode == FirmwareCpuMode::Unknown);
    }

    // Flat raw code can preselect an ARM instruction-set mode without claiming
    // a firmware container/mapping. Each fixture contains coherent prologue,
    // frame-setup, call and return motifs at the mode's natural alignment.
    {
        std::vector<uint8_t> a32(1024, 0);
        for (size_t off = 0; off < 4 * 16; off += 16) {
            put32(a32, off + 0, 0xe92d4800u); // push {r11,lr}
            put32(a32, off + 4, 0xe28db004u); // add r11,sp,#4
            put32(a32, off + 8, 0xeb000001u); // bl
            put32(a32, off + 12, 0xe8bd8800u);// pop {r11,pc}
        }
        FirmwareDetection d = SniffFirmware(a32);
        CHECK(!d.detected() && !d.recommendedImageBaseValid);
        CHECK(d.architecture.mode == FirmwareCpuMode::ARM_A32);
        CHECK(d.architecture.confidence >= FirmwareConfidence::Medium);
        CHECK(d.architecture.evidence.find("A32=") != std::string::npos);
        CHECK(d.architecture.evidence.find("sampled [+0x") != std::string::npos);
    }
    {
        std::vector<uint8_t> thumb(1024, 0);
        for (size_t off = 0; off < 4 * 10; off += 10) {
            put16(thumb, off + 0, 0xb5b0u); // push {...,lr}
            put16(thumb, off + 2, 0xb082u); // sub sp,#8
            put16(thumb, off + 4, 0xf000u); // BL first half
            put16(thumb, off + 6, 0xf800u); // BL second half
            put16(thumb, off + 8, 0xbdb0u); // pop {...,pc}
        }
        FirmwareDetection d = SniffFirmware(thumb);
        CHECK(!d.detected());
        CHECK(d.architecture.mode == FirmwareCpuMode::ARM_Thumb);
        CHECK(d.architecture.confidence >= FirmwareConfidence::Medium);
    }
    {
        std::vector<uint8_t> a64(1024, 0);
        for (size_t off = 0; off < 4 * 16; off += 16) {
            put32(a64, off + 0, 0xa9bf7bfdu); // stp x29,x30,[sp,#-16]!
            put32(a64, off + 4, 0x910003fdu); // mov x29,sp
            put32(a64, off + 8, 0x94000001u); // bl
            put32(a64, off + 12, 0xd65f03c0u);// ret
        }
        FirmwareDetection d = SniffFirmware(a64);
        CHECK(!d.detected());
        CHECK(d.architecture.mode == FirmwareCpuMode::ARM_AArch64);
        CHECK(d.architecture.confidence >= FirmwareConfidence::Medium);
    }

    // ---- standalone jump resolver -----------------------------------------
    {
        std::vector<uint8_t> b(0x10000, 0x90);
        const uint64_t base = 0xffff0000ull;

        b[0x100] = 0xeb; b[0x101] = 0x10;
        FirmwareJump j = ResolveFirmwareX86Jump(b.data(), b.size(), 0x100, base);
        CHECK(j.recognized && j.targetResolved && j.instructionLength == 2);
        CHECK(j.target.fileOffset == 0x112 && j.target.virtualAddress == 0xffff0112ull);

        b[0x200] = 0xe9; put16(b, 0x201, static_cast<uint16_t>(-0x23));
        j = ResolveFirmwareX86Jump(b.data(), b.size(), 0x200, base);
        CHECK(j.recognized && j.targetResolved && j.target.fileOffset == 0x1e0);

        b[0x300] = 0x66; b[0x301] = 0xe9; put32(b, 0x302, 0x20);
        j = ResolveFirmwareX86Jump(b.data(), b.size(), 0x300, base);
        CHECK(j.recognized && j.targetResolved && j.instructionLength == 6);
        CHECK(j.target.fileOffset == 0x326);

        // EA F000:0100 maps through the real-mode alias to this ROM's +100h.
        b[0xfff0] = 0xea; put16(b, 0xfff1, 0x0100); put16(b, 0xfff3, 0xf000);
        j = ResolveFirmwareX86Jump(b.data(), b.size(), 0xfff0, base);
        CHECK(j.recognized && j.targetResolved && j.form == "far immediate");
        CHECK(j.target.fileOffset == 0x100 && j.target.virtualAddress == 0xffff0100ull);

        // rel16 wraps IP at the 64-KiB boundary in real mode.
        b[0xfff0] = 0xe9; put16(b, 0xfff1, 0x010d); // FFF3 + 010D -> 0100
        j = ResolveFirmwareX86Jump(b.data(), b.size(), 0xfff0, base);
        CHECK(j.recognized && j.targetResolved && j.target.fileOffset == 0x100);

        b[0xfff0] = 0xea; // truncated far pointer in a 3-byte view
        j = ResolveFirmwareX86Jump(b.data() + 0xfff0, 3, 0, base);
        CHECK(!j.recognized && !j.targetResolved);

        b[0] = 0xea; put16(b, 1, 0); put16(b, 3, 0x1000); // outside C0000 ROM mapping
        j = ResolveFirmwareX86Jump(b.data(), b.size(), 0, 0x000c0000ull);
        CHECK(j.recognized && !j.targetResolved);

        b[0] = 0xeb; b[1] = 0;
        j = ResolveFirmwareX86Jump(b.data(), b.size(), 0,
                                   std::numeric_limits<uint64_t>::max());
        CHECK(j.recognized && j.targetResolved);
        CHECK(j.source.virtualAddressValid &&
              j.source.virtualAddress == std::numeric_limits<uint64_t>::max());
        CHECK(!j.target.virtualAddressValid);
    }

    // ---- legacy BIOS: reset mapping, tail date, checksum, entry seed -------
    {
        std::vector<uint8_t> bios(0x10000, 0xff);
        const size_t reset = bios.size() - 16;
        bios[reset] = 0xea;
        put16(bios, reset + 1, 0x0100);
        put16(bios, reset + 3, 0xf000);
        const char date[] = "07/12/26";
        std::copy(date, date + 8, bios.begin() + static_cast<ptrdiff_t>(reset + 5));
        bios[0x100] = 0x90;
        fixChecksum8(bios, 0, bios.size());

        FirmwareDetection d = SniffFirmware(bios);
        CHECK(d.has(FirmwareKind::LegacyBios));
        CHECK(d.primaryKind == FirmwareKind::LegacyBios);
        CHECK(d.confidence == FirmwareConfidence::High);
        CHECK(d.recommendedImageBaseValid && d.recommendedImageBase == 0xffff0000ull);
        CHECK(d.entry.detected && d.entry.location.fileOffset == 0x100);
        CHECK(d.entry.location.virtualAddressValid &&
              d.entry.location.virtualAddress == 0xffff0100ull);
        CHECK(d.entry.mode == FirmwareCpuMode::X86Real16);
        CHECK(d.entry.confidence == FirmwareConfidence::High);
        CHECK(d.entry.jumpChain.size() == 1);
        CHECK(d.architecture.mode == FirmwareCpuMode::X86Real16);
        CHECK(hasLandmark(d, "reset_vector", reset));
        CHECK(hasLandmark(d, "firmware_boot_entry", 0x100));
        CHECK(!d.mappingEvidence.empty() && !d.entry.evidence.empty());
    }

    // A lone jump opcode at the tail is useful low-confidence evidence, but is
    // not enough to call arbitrary data a legacy BIOS.
    {
        std::vector<uint8_t> b(0x10000, 0x41);
        b[b.size() - 16] = 0xeb; b[b.size() - 15] = 0xfe;
        FirmwareDetection d = SniffFirmware(b);
        CHECK(!d.has(FirmwareKind::LegacyBios));
        CHECK(d.entry.detected);
        CHECK(d.entry.confidence == FirmwareConfidence::Low);
        CHECK(!d.recommendedImageBaseValid);
    }

    // ---- PI firmware volume and embedded PE architecture ------------------
    {
        std::vector<uint8_t> b = makeFv(4096, 0x100, 0x800, true);
        FirmwareDetection d = SniffFirmware(b);
        CHECK(d.has(FirmwareKind::UefiFirmware));
        CHECK(d.primaryKind == FirmwareKind::UefiFirmware);
        CHECK(d.firmwareVolumes.size() == 1);
        if (!d.firmwareVolumes.empty()) {
            const auto& fv = d.firmwareVolumes[0];
            CHECK(fv.fileOffset == 0x100 && fv.length == 0x800);
            CHECK(fv.complete && fv.checksumValid && fv.blockMapTerminated);
            CHECK(fv.knownFileSystemGuid && fv.revision == 2);
            CHECK(fv.confidence == FirmwareConfidence::High);
        }
        CHECK(d.architecture.mode == FirmwareCpuMode::X86_64);
        CHECK(d.architecture.confidence == FirmwareConfidence::High);
        CHECK(hasLandmark(d, "uefi_fv_0", 0x100));
        CHECK(hasLandmark(d, "uefi_image_0", 0x200));
        CHECK(!d.entry.detected); // an FV is not itself a CPU entry-point claim
        CHECK(!d.recommendedImageBaseValid); // standalone FVs need no top-map claim
    }
    {
        std::vector<uint8_t> malformed(512, 0);
        malformed[0x28] = '_'; malformed[0x29] = 'F';
        malformed[0x2a] = 'V'; malformed[0x2b] = 'H';
        put64(malformed, 0x20, std::numeric_limits<uint64_t>::max());
        put16(malformed, 0x30, 0x48);
        malformed[0x37] = 2;
        FirmwareDetection d = SniffFirmware(malformed);
        CHECK(!d.has(FirmwareKind::UefiFirmware));
        CHECK(d.firmwareVolumes.empty());
    }

    // ---- PCIR-backed legacy and EFI option ROMs ---------------------------
    {
        std::vector<uint8_t> rom = makeLegacyOptionRom();
        FirmwareDetection d = SniffFirmware(rom);
        CHECK(d.has(FirmwareKind::PciOptionRom));
        CHECK(d.primaryKind == FirmwareKind::PciOptionRom);
        CHECK(d.optionRoms.size() == 1);
        if (!d.optionRoms.empty()) {
            const auto& r = d.optionRoms[0];
            CHECK(r.vendorId == 0x1234 && r.deviceId == 0xabcd);
            CHECK(r.declaredSize == 1024 && r.pcirOffset == 0x1c);
            CHECK(r.codeType == 0 && r.lastImage && r.complete && r.checksumValid);
            CHECK(!r.efiImage && r.confidence == FirmwareConfidence::High);
        }
        CHECK(d.recommendedImageBaseValid && d.recommendedImageBase == 0xc0000ull);
        CHECK(d.architecture.mode == FirmwareCpuMode::X86Real16);
        CHECK(d.entry.detected && d.entry.location.fileOffset == 0x80);
        CHECK(d.entry.location.virtualAddress == 0xc0080ull);
        CHECK(hasLandmark(d, "pci_option_rom_0", 0));
        CHECK(hasLandmark(d, "pcir_0", 0x1c));
        CHECK(hasLandmark(d, "pci_init_0", 0x80));
    }
    {
        // Strong PCIR machine evidence wins even when an unused region contains
        // enough coherent AArch64 motifs to score positively.
        std::vector<uint8_t> rom = makeLegacyOptionRom();
        for (size_t off = 0x100; off < 0x180; off += 16) {
            put32(rom, off + 0, 0xa9bf7bfdu); put32(rom, off + 4, 0x910003fdu);
            put32(rom, off + 8, 0x94000001u); put32(rom, off + 12, 0xd65f03c0u);
        }
        fixChecksum8(rom, 0, rom.size());
        FirmwareDetection d = SniffFirmware(rom);
        CHECK(d.architecture.mode == FirmwareCpuMode::X86Real16);
        CHECK(d.architecture.confidence == FirmwareConfidence::High);
    }
    {
        std::vector<uint8_t> rom = makeEfiOptionRom();
        FirmwareDetection d = SniffFirmware(rom);
        CHECK(d.has(FirmwareKind::PciOptionRom));
        CHECK(d.optionRoms.size() == 1 && d.optionRoms[0].efiImage);
        CHECK(d.optionRoms[0].efiMachine == 0x8664);
        CHECK(d.optionRoms[0].efiCompressionType == 0);
        CHECK(d.architecture.mode == FirmwareCpuMode::X86_64);
        CHECK(d.entry.detected && d.entry.mode == FirmwareCpuMode::X86_64);
        CHECK(d.entry.location.fileOffset == 0x280 &&
              d.entry.location.virtualAddress == 0xc0280ull);
        CHECK(hasLandmark(d, "pci_efi_image_0", 0x80));
        CHECK(hasLandmark(d, "pci_efi_entry_0", 0x280));
    }
    {
        std::vector<uint8_t> rom = makeEfiOptionRom();
        put16(rom, 0x0c, 1); // UEFI compression: payload is not directly decodable
        fixChecksum8(rom, 0, rom.size());
        FirmwareDetection d = SniffFirmware(rom);
        CHECK(d.has(FirmwareKind::PciOptionRom));
        CHECK(d.optionRoms.size() == 1 && d.optionRoms[0].efiCompressionType == 1);
        CHECK(d.architecture.mode == FirmwareCpuMode::X86_64); // header remains evidence
        CHECK(!d.entry.detected); // compressed payload is not exposed as a code entry
        const auto it = std::find_if(d.landmarks.begin(), d.landmarks.end(),
            [](const FirmwareLandmark& l) { return l.name == "pci_efi_image_0"; });
        CHECK(it != d.landmarks.end() && !it->code);
    }
    {
        std::vector<uint8_t> fake(1024, 0);
        fake[0] = 0x55; fake[1] = 0xaa; fake[2] = 2;
        put16(fake, 0x18, 0xfff0); // PCIR pointer outside image
        FirmwareDetection d = SniffFirmware(fake);
        CHECK(!d.has(FirmwareKind::PciOptionRom));
        CHECK(d.optionRoms.empty());
    }

    // ---- Intel flash descriptor and bounded BIOS region -------------------
    {
        std::vector<uint8_t> flash(1024 * 1024, 0xff);
        put32(flash, 0x10, 0x0ff0a55a);
        put32(flash, 0x14, 4u << 16); // FRBA = 40h
        put32(flash, 0x40, 0);       // descriptor region = [0, FFFh]
        const uint32_t lastPage = static_cast<uint32_t>(flash.size() / 4096 - 1);
        put32(flash, 0x44, 1u | (lastPage << 16));

        FirmwareDetection d = SniffFirmware(flash);
        CHECK(d.has(FirmwareKind::IntelFlashDescriptor));
        CHECK(d.primaryKind == FirmwareKind::IntelFlashDescriptor);
        CHECK(d.flashDescriptors.size() == 1);
        if (!d.flashDescriptors.empty()) {
            const auto& fd = d.flashDescriptors[0];
            CHECK(fd.fileOffset == 0 && fd.regionTableOffset == 0x40);
            CHECK(fd.mapValid && fd.biosRegionValid);
            CHECK(fd.biosRegionOffset == 0x1000);
            CHECK(fd.biosRegionSize == flash.size() - 0x1000);
            CHECK(fd.confidence == FirmwareConfidence::High);
        }
        CHECK(d.recommendedImageBaseValid && d.recommendedImageBase == 0xfff00000ull);
        CHECK(hasLandmark(d, "intel_flash_descriptor_0", 0));
        CHECK(hasLandmark(d, "bios_region_0", 0x1000));
    }
    {
        std::vector<uint8_t> flash(8192, 0xff);
        put32(flash, 0x10, 0x0ff0a55a);
        put32(flash, 0x14, 0xffu << 16); // FRBA points outside descriptor
        FirmwareDetection d = SniffFirmware(flash);
        CHECK(d.has(FirmwareKind::IntelFlashDescriptor));
        CHECK(d.flashDescriptors.size() == 1);
        CHECK(!d.flashDescriptors[0].mapValid);
        CHECK(!d.flashDescriptors[0].biosRegionValid);
        CHECK(d.flashDescriptors[0].confidence == FirmwareConfidence::Medium);
    }

    // ---- bounded scans and record caps ------------------------------------
    {
        std::vector<uint8_t> b = makeFv(8192, 0x1000, 0x800, false);
        FirmwareSniffOptions options;
        options.maxScanBytes = 128; // deterministic 64-byte head/tail windows
        options.maxEvidence = 1;
        FirmwareDetection d = SniffFirmware(b, options);
        CHECK(d.scanTruncated);
        CHECK(!d.has(FirmwareKind::UefiFirmware)); // middle signature was not scanned
        CHECK(d.evidence.size() <= 1);
    }
    {
        // The fixed descriptor-at-10h check remains active even when pattern
        // scanning is disabled.
        std::vector<uint8_t> flash(8192, 0);
        put32(flash, 0x10, 0x0ff0a55a);
        put32(flash, 0x14, 4u << 16);
        put32(flash, 0x40, 0);
        put32(flash, 0x44, 1u | (1u << 16));
        FirmwareSniffOptions options;
        options.maxScanBytes = 0;
        FirmwareDetection d = SniffFirmware(flash, options);
        CHECK(d.scanTruncated);
        CHECK(d.has(FirmwareKind::IntelFlashDescriptor));
    }

    CHECK(std::string(FirmwareConfidenceName(FirmwareConfidence::High)) == "high");
    CHECK(std::string(FirmwareKindName(FirmwareKind::UefiFirmware)) == "UEFI firmware");
    CHECK(std::string(FirmwareCpuModeName(FirmwareCpuMode::X86Real16)) == "x86-16 real mode");
    CHECK(std::string(FirmwareCpuModeName(FirmwareCpuMode::ARM_Thumb)) == "Thumb/Thumb-2");

    if (g_fail == 0) std::printf("ALL FIRMWARE SNIFFER TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
