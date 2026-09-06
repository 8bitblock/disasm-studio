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

static void le16(std::vector<uint8_t>& b, size_t o, uint16_t v) {
    b[o] = uint8_t(v); b[o + 1] = uint8_t(v >> 8);
}
static void le32(std::vector<uint8_t>& b, size_t o, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) b[o + i] = uint8_t(v >> (i * 8));
}
static void le64(std::vector<uint8_t>& b, size_t o, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) b[o + i] = uint8_t(v >> (i * 8));
}
static void be32(std::vector<uint8_t>& b, size_t o, uint32_t v) {
    for (unsigned i = 0; i < 4; ++i) b[o + i] = uint8_t(v >> ((3 - i) * 8));
}
static void be64(std::vector<uint8_t>& b, size_t o, uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) b[o + i] = uint8_t(v >> ((7 - i) * 8));
}
static void fixed(std::vector<uint8_t>& b, size_t o, const char* text, size_t cap) {
    std::memset(b.data() + o, 0, cap);
    std::memcpy(b.data() + o, text, std::min(cap, std::strlen(text)));
}
static size_t align4(size_t value) { return (value + 3u) & ~size_t{3}; }

static std::vector<uint8_t> buildThin64(uint64_t mainEntryOffset = 0x300,
                                        bool includeMain = true) {
    constexpr uint64_t base = 0x100000000ull;
    std::vector<uint8_t> b(0x900, 0);
    le32(b, 0, 0xfeedfacfu);
    le32(b, 4, 0x01000007u); // x86_64
    le32(b, 8, 3);
    le32(b, 12, 2);          // MH_EXECUTE
    le32(b, 24, 0);
    le32(b, 28, 0);

    size_t lc = 32;
    uint32_t ncmds = 0;
    auto command = [&](uint32_t type, uint32_t size) {
        const size_t here = lc;
        le32(b, here, type); le32(b, here + 4, size);
        lc += size; ++ncmds;
        return here;
    };

    size_t c = command(0x19, 72 + 80); // __TEXT + __text
    fixed(b, c + 8, "__TEXT", 16);
    le64(b, c + 24, base); le64(b, c + 32, 0x500);
    le64(b, c + 40, 0); le64(b, c + 48, 0x500);
    le32(b, c + 56, 7); le32(b, c + 60, 5); le32(b, c + 64, 1);
    size_t s = c + 72;
    fixed(b, s, "__text", 16); fixed(b, s + 16, "__TEXT", 16);
    le64(b, s + 32, base + 0x300); le64(b, s + 40, 0x80);
    le32(b, s + 48, 0x300); le32(b, s + 52, 4);
    le32(b, s + 64, 0x80000400u);

    c = command(0x19, 72 + 80); // __DATA + __mod_init_func
    fixed(b, c + 8, "__DATA", 16);
    le64(b, c + 24, base + 0x1000); le64(b, c + 32, 0x100);
    le64(b, c + 40, 0x500); le64(b, c + 48, 0x100);
    le32(b, c + 56, 3); le32(b, c + 60, 3); le32(b, c + 64, 1);
    s = c + 72;
    fixed(b, s, "__mod_init_func", 16); fixed(b, s + 16, "__DATA", 16);
    le64(b, s + 32, base + 0x1000); le64(b, s + 40, 16);
    le32(b, s + 48, 0x500); le32(b, s + 52, 3); le32(b, s + 64, 0x09);

    c = command(0x02, 24); // LC_SYMTAB
    le32(b, c + 8, 0x600); le32(b, c + 12, 3);
    le32(b, c + 16, 0x640); le32(b, c + 20, 0x40);

    const std::string dylib = "/usr/lib/libSystem.B.dylib";
    const uint32_t dylibSize = static_cast<uint32_t>(align4(24 + dylib.size() + 1));
    c = command(0x0c, dylibSize);
    le32(b, c + 8, 24);
    std::memcpy(b.data() + c + 24, dylib.c_str(), dylib.size() + 1);

    c = command(0x80000022u, 48); // LC_DYLD_INFO_ONLY
    le32(b, c + 16, 0x700); le32(b, c + 20, 11); // bind_off / bind_size

    c = command(0x80000033u, 16); // LC_DYLD_EXPORTS_TRIE
    le32(b, c + 8, 0x720); le32(b, c + 12, 16);

    c = command(0x26, 16); // LC_FUNCTION_STARTS
    le32(b, c + 8, 0x750); le32(b, c + 12, 4);

    if (includeMain) {
        c = command(0x80000028u, 24); // LC_MAIN
        le64(b, c + 8, mainEntryOffset);
    }

    c = command(0x1a, 72); // LC_ROUTINES_64
    le64(b, c + 8, base + 0x320);

    le32(b, 16, ncmds);
    le32(b, 20, static_cast<uint32_t>(lc - 32));
    CHECK(lc <= 0x300);

    // Two initializer pointers, including an explicit zero value.
    le64(b, 0x500, base + 0x320);
    le64(b, 0x508, 0);

    // nlist_64 rows: two definitions and one dylib import.
    le32(b, 0x600, 1);  b[0x604] = 0x0f; b[0x605] = 1; le64(b, 0x608, base + 0x300);
    le32(b, 0x610, 7);  b[0x614] = 0x0f; b[0x615] = 2; le64(b, 0x618, base + 0x1008);
    le32(b, 0x620, 15); b[0x624] = 0x01; b[0x625] = 0; le16(b, 0x626, 0x0100);
    const char strings[] = "\0_main\0_global\0_puts\0";
    std::memcpy(b.data() + 0x640, strings, sizeof(strings));

    // Bind _puts at __DATA + 0.
    const uint8_t bind[] = {0x11, 0x40, '_','p','u','t','s',0, 0x51, 0x71, 0x00, 0x90, 0x00};
    // The stream declared above intentionally excludes the two bytes before
    // SET_SEGMENT; copy the compact stream used by the parser explicitly.
    const uint8_t compactBind[] = {0x11, 0x40, '_','p','u','t','s',0, 0x71, 0x00, 0x90};
    (void)bind;
    std::memcpy(b.data() + 0x700, compactBind, sizeof(compactBind));

    // Root -> "_export" -> terminal(flags=0,address=0x310).
    const uint8_t trie[] = {0x00,0x01,'_','e','x','p','o','r','t',0x00,0x0b,
                            0x03,0x00,0x90,0x06,0x00};
    std::memcpy(b.data() + 0x720, trie, sizeof(trie));

    // Deltas 0x300, 0x10, terminator.
    const uint8_t starts[] = {0x80,0x06,0x10,0x00};
    std::memcpy(b.data() + 0x750, starts, sizeof(starts));
    b[0x300] = 0xc3;
    b[0x310] = 0xc3;
    b[0x320] = 0xc3;
    return b;
}

static std::vector<uint8_t> buildFat(bool fat64) {
    auto thin = buildThin64();
    const size_t x64Offset = 0x2000;
    std::vector<uint8_t> b(x64Offset + thin.size(), 0);
    be32(b, 0, fat64 ? 0xcafebabfu : 0xcafebabeu);
    be32(b, 4, fat64 ? 1 : 2);
    size_t row = 8;
    if (!fat64) {
        // ARM64 appears first, but the parser's stable preference selects x64.
        be32(b, row, 0x0100000c); be32(b, row + 4, 0);
        be32(b, row + 8, 0x1000); be32(b, row + 12, 0x100); be32(b, row + 16, 12);
        be32(b, 0x1000, 0xfeedfacf); be32(b, 0x1004, 0x0100000c);
        row += 20;
        be32(b, row, 0x01000007); be32(b, row + 4, 3);
        be32(b, row + 8, static_cast<uint32_t>(x64Offset));
        be32(b, row + 12, static_cast<uint32_t>(thin.size())); be32(b, row + 16, 12);
    } else {
        be32(b, row, 0x01000007); be32(b, row + 4, 3);
        be64(b, row + 8, x64Offset); be64(b, row + 16, thin.size());
        be32(b, row + 24, 12); be32(b, row + 28, 0);
    }
    std::copy(thin.begin(), thin.end(), b.begin() + x64Offset);
    return b;
}

static std::vector<uint8_t> buildBigEndian32() {
    std::vector<uint8_t> b(0x200, 0);
    be32(b, 0, 0xfeedface); be32(b, 4, 0x12); // PPC
    be32(b, 8, 0); be32(b, 12, 2); be32(b, 16, 1); be32(b, 20, 124);
    const size_t lc = 28;
    be32(b, lc, 1); be32(b, lc + 4, 124);
    fixed(b, lc + 8, "__TEXT", 16);
    be32(b, lc + 24, 0x1000); be32(b, lc + 28, 0x1000);
    be32(b, lc + 32, 0); be32(b, lc + 36, 0x200);
    be32(b, lc + 40, 7); be32(b, lc + 44, 5); be32(b, lc + 48, 1);
    const size_t s = lc + 56;
    fixed(b, s, "__text", 16); fixed(b, s + 16, "__TEXT", 16);
    be32(b, s + 32, 0x1000); be32(b, s + 36, 0x80);
    be32(b, s + 40, 0x100); be32(b, s + 44, 2); be32(b, s + 56, 0x80000400u);
    return b;
}

static bool loadBytes(const char* name, const std::vector<uint8_t>& bytes, BinaryFile& out) {
    { std::ofstream f(name, std::ios::binary); f.write(reinterpret_cast<const char*>(bytes.data()),
                                                        static_cast<std::streamsize>(bytes.size())); }
    const bool ok = out.load(name);
    std::remove(name);
    return ok;
}

int main() {
    constexpr uint64_t base = 0x100000000ull;
    {
        BinaryFile bin;
        CHECK(loadBytes("macho_metadata_thin.bin", buildThin64(), bin));
        CHECK(bin.format() == BinFormat::MachO && bin.machine() == MachineArch::X64 && bin.is64Bit());
        CHECK(bin.hasEntryPoint() && bin.entryPointVA() == base + 0x300);
        const auto& m = bin.machO();
        CHECK(!m.universal && m.selectedSlice == 0 && m.slices.size() == 1);
        CHECK(m.loadCommandsValid && !m.loadCommandsTruncated);
        CHECK(m.symbolTablePresent && m.symbolTableValid && m.symbols.size() == 3);
        CHECK(std::any_of(m.symbols.begin(), m.symbols.end(), [](const auto& s) {
            return s.name == "_main" && s.mapped && s.isCode && !s.undefined;
        }));
        CHECK(std::any_of(bin.imports().begin(), bin.imports().end(), [](const auto& i) {
            return i.name == "_puts" && i.dll == "/usr/lib/libSystem.B.dylib";
        }));
        CHECK(m.bindingsPresent && m.bindingsValid && m.bindings.size() == 1);
        if (m.bindings.size() == 1) {
            CHECK(m.bindings[0].addressValid && m.bindings[0].address == base + 0x1000);
            CHECK(m.bindings[0].symbol == "_puts" && m.bindings[0].mapped);
        }
        CHECK(m.exportTriePresent && m.exportTrieValid && m.trieExports.size() == 1);
        if (m.trieExports.size() == 1) {
            CHECK(m.trieExports[0].name == "_export");
            CHECK(m.trieExports[0].addressValid && m.trieExports[0].address == base + 0x310);
        }
        CHECK(m.functionStartsPresent && m.functionStartsValid && m.functionStarts.size() == 2);
        if (m.functionStarts.size() == 2) {
            CHECK(m.functionStarts[0] == base + 0x300);
            CHECK(m.functionStarts[1] == base + 0x310);
        }
        CHECK(m.initializersPresent && m.initializersValid && m.initializers.size() == 3);
        CHECK(std::any_of(m.initializers.begin(), m.initializers.end(), [](const auto& i) {
            return i.kind == BinaryFile::MachOInitializerKind::ModInitSection &&
                   i.targetValid && i.targetVA == 0;
        }));
    }
    {
        auto dylib = buildThin64(0, false);
        le32(dylib, 12, 6); // MH_DYLIB: no LC_MAIN and no process entry
        BinaryFile bin;
        CHECK(loadBytes("macho_metadata_dylib_no_main.bin", dylib, bin));
        CHECK(!bin.hasEntryPoint());
    }
    {
        BinaryFile bin;
        CHECK(loadBytes("macho_metadata_bad_main.bin", buildThin64(0x880), bin));
        CHECK(!bin.hasEntryPoint()); // points outside every executable section
    }
    {
        BinaryFile bin;
        CHECK(loadBytes("macho_metadata_fat.bin", buildFat(false), bin));
        const auto& m = bin.machO();
        CHECK(bin.format() == BinFormat::MachO && m.universal && !m.fat64);
        CHECK(m.slices.size() == 2 && m.selectedSlice == 1 && m.slices[1].selected);
        uint64_t offset = 0;
        CHECK(bin.vaToOffset(base + 0x300, offset) && offset == 0x2300);
        CHECK(std::string(bin.formatName()) == "Mach-O Universal");
    }
    {
        BinaryFile bin;
        CHECK(loadBytes("macho_metadata_fat64.bin", buildFat(true), bin));
        CHECK(bin.format() == BinFormat::MachO && bin.machO().universal && bin.machO().fat64);
        CHECK(bin.machO().selectedSlice == 0);
    }
    {
        BinaryFile bin;
        CHECK(loadBytes("macho_metadata_be.bin", buildBigEndian32(), bin));
        CHECK(bin.format() == BinFormat::MachO && bin.machine() == MachineArch::PPC && !bin.is64Bit());
        CHECK(bin.bigEndian());
        CHECK(bin.machO().slices.size() == 1 && bin.machO().slices[0].bigEndian);
        uint64_t off = 0;
        CHECK(bin.vaToOffset(0x1000, off) && off == 0x100);
    }
    {
        auto malformed = buildThin64();
        le32(malformed, 0x600, 0xfffffff0u); // bad n_strx
        // Unterminated binding ULEB and function-start stream; cyclic export trie.
        malformed[0x700] = 0x20; malformed[0x701] = 0x80;
        const uint8_t cycle[] = {0x00,0x01,'a',0x00,0x00};
        std::memcpy(malformed.data() + 0x720, cycle, sizeof(cycle));
        // Locate the linkedit commands and reduce their declared ranges.
        size_t lc = 32;
        const uint32_t ncmds = uint32_t(malformed[16]) | (uint32_t(malformed[17]) << 8);
        for (uint32_t i = 0; i < ncmds; ++i) {
            const uint32_t cmd = uint32_t(malformed[lc]) | (uint32_t(malformed[lc + 1]) << 8) |
                                 (uint32_t(malformed[lc + 2]) << 16) | (uint32_t(malformed[lc + 3]) << 24);
            const uint32_t size = uint32_t(malformed[lc + 4]) | (uint32_t(malformed[lc + 5]) << 8) |
                                  (uint32_t(malformed[lc + 6]) << 16) | (uint32_t(malformed[lc + 7]) << 24);
            if (cmd == 0x80000022u) le32(malformed, lc + 20, 2);
            if (cmd == 0x80000033u) le32(malformed, lc + 12, sizeof(cycle));
            if (cmd == 0x26u) le32(malformed, lc + 12, 3); // 0x300,0x10; no zero terminator
            lc += size;
        }
        BinaryFile bin;
        CHECK(loadBytes("macho_metadata_bad.bin", malformed, bin));
        CHECK(bin.format() == BinFormat::MachO);
        CHECK(!bin.machO().symbolTableValid);
        CHECK(!bin.machO().bindingsValid && bin.machO().bindingsTruncated);
        CHECK(!bin.machO().exportTrieValid && bin.machO().exportTrieTruncated);
        CHECK(!bin.machO().functionStartsValid && bin.machO().functionStartsTruncated);
    }
    {
        std::vector<uint8_t> badFat(64, 0);
        be32(badFat, 0, 0xcafebabe); be32(badFat, 4, 1);
        be32(badFat, 8, 0x01000007); be32(badFat, 16, 0xfffff000u);
        be32(badFat, 20, 0x1000); be32(badFat, 24, 12);
        BinaryFile bin;
        CHECK(!loadBytes("macho_metadata_badfat.bin", badFat, bin));
        CHECK(!bin.loaded() && bin.format() == BinFormat::Unknown &&
              bin.machO().slices.empty());
    }

    if (!g_fail) std::printf("ALL MACH-O METADATA TESTS PASSED\n");
    else std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
