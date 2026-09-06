//
// techscan_multi_test.cpp
// Off-target test for the multi-hit collection in src/Core/TechScan.cpp: byte-pattern
// capability detection must collect ALL (bounded) occurrences of a signature, not just
// the first, and surface the count + every address. Exercised via the "Direct syscall
// stub" pattern (the crypto-constant signatures moved to Core/AlgoScan; see
// tests/algoscan_test.cpp).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\techscan_multi_test.cpp ^
//       src\Core\TechScan.cpp src\Core\JavaScan.cpp src\Core\RuntimeScan.cpp src\Core\Inflate.cpp ^
//       src\Core\NetworkApiCatalog.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
//   .\techscan_multi_test.exe
//
#include "Core/TechScan.h"
#include "Core/BinaryFile.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

// Direct syscall stub: 4C 8B D1 B8 ?? ?? ?? ?? 0F 05 (the imm32 is wildcarded). The 4
// filler bytes match the wildcards, so any value is fine.
static const uint8_t kStub[10]    = { 0x4C,0x8B,0xD1, 0xB8, 0x11,0x22,0x33,0x44, 0x0F,0x05 };
static const char*   kStubName    = "Direct syscall stub";

static const Capability* find(const std::vector<Capability>& caps, const char* name) {
    for (const auto& c : caps) if (c.name == name) return &c;
    return nullptr;
}

// Write `bytes` to a temp file and loadRaw it at `base` (Raw -> offsetToVA = base+off).
static bool loadBlob(BinaryFile& bf, const std::vector<uint8_t>& bytes, uint64_t base) {
    char tmp[L_tmpnam_s]; if (tmpnam_s(tmp, sizeof(tmp)) != 0) return false;
    std::string path = std::string(tmp);
    { std::ofstream f(path, std::ios::binary); f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
    bool ok = bf.loadRaw(path, base);
    std::remove(path.c_str());
    return ok;
}

struct ImportFixtureGroup {
    std::string dll;
    std::vector<std::string> names;
};

// Minimal PE32 with one .rdata section containing a bounded ordinary import
// directory. This exercises TechScan through BinaryFile's real parser rather
// than reaching around it with a test-only import seam.
static std::vector<uint8_t> importFixturePe(
    const std::vector<ImportFixtureGroup>& groups) {
    constexpr size_t kRaw = 0x200;
    constexpr uint32_t kRva = 0x1000;
    std::vector<uint8_t> b(0xA00, 0);
    auto put16 = [&](size_t off, uint16_t value) {
        std::memcpy(b.data() + off, &value, sizeof(value));
    };
    auto put32 = [&](size_t off, uint32_t value) {
        std::memcpy(b.data() + off, &value, sizeof(value));
    };
    auto asRva = [&](size_t off) { return kRva + static_cast<uint32_t>(off - kRaw); };
    auto align = [](size_t value, size_t amount) {
        return (value + amount - 1) & ~(amount - 1);
    };

    b[0] = 'M'; b[1] = 'Z'; put32(0x3C, 0x80); put32(0x80, 0x00004550);
    const size_t coff = 0x84;
    put16(coff + 0, 0x014C); put16(coff + 2, 1);
    put16(coff + 16, 0xE0); put16(coff + 18, 0x0102);
    const size_t opt = coff + 20;
    put16(opt + 0, 0x10B); put32(opt + 16, 0x1000); put32(opt + 28, 0x400000);
    put32(opt + 32, 0x1000); put32(opt + 36, 0x200); put32(opt + 56, 0x2000);
    put32(opt + 60, 0x200); put32(opt + 92, 16);
    put32(opt + 96 + 8, kRva);
    put32(opt + 96 + 12, static_cast<uint32_t>((groups.size() + 1) * 20));
    const size_t sec = opt + 0xE0;
    std::memcpy(b.data() + sec, ".rdata\0\0", 8);
    put32(sec + 8, 0x800); put32(sec + 12, kRva);
    put32(sec + 16, 0x800); put32(sec + 20, static_cast<uint32_t>(kRaw));
    put32(sec + 36, 0x40000040u);

    size_t cursor = align(kRaw + (groups.size() + 1) * 20, 16);
    for (size_t groupIndex = 0; groupIndex < groups.size(); ++groupIndex) {
        const ImportFixtureGroup& group = groups[groupIndex];
        const size_t oft = cursor;
        cursor += (group.names.size() + 1) * sizeof(uint32_t);
        const size_t iat = cursor;
        cursor += (group.names.size() + 1) * sizeof(uint32_t);
        const size_t dll = cursor;
        std::memcpy(b.data() + cursor, group.dll.c_str(), group.dll.size() + 1);
        cursor = align(cursor + group.dll.size() + 1, 2);

        for (size_t nameIndex = 0; nameIndex < group.names.size(); ++nameIndex) {
            const size_t hintName = cursor;
            put16(hintName, 0);
            std::memcpy(b.data() + hintName + 2, group.names[nameIndex].c_str(),
                        group.names[nameIndex].size() + 1);
            cursor = align(hintName + 2 + group.names[nameIndex].size() + 1, 2);
            put32(oft + nameIndex * 4, asRva(hintName));
            put32(iat + nameIndex * 4, asRva(hintName));
        }

        const size_t descriptor = kRaw + groupIndex * 20;
        put32(descriptor + 0, asRva(oft));
        put32(descriptor + 12, asRva(dll));
        put32(descriptor + 16, asRva(iat));
    }
    CHECK(cursor <= b.size());
    return b;
}

static bool loadPe(BinaryFile& binary, const std::vector<uint8_t>& bytes,
                   const char* path) {
    { std::ofstream file(path, std::ios::binary);
      file.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size())); }
    const bool loaded = binary.load(path);
    std::remove(path);
    return loaded;
}

int main() {
    const uint64_t base = 0x400000;

    // A real match at VA zero must remain navigable; zero is not a
    // missing-address sentinel.
    {
        std::vector<uint8_t> blob(kStub, kStub + sizeof(kStub));
        BinaryFile bf;
        CHECK(loadBlob(bf, blob, 0));
        const std::vector<Capability> caps = ScanCapabilities(bf);
        const Capability* st = find(caps, kStubName);
        CHECK(st != nullptr);
        if (st) CHECK(st->addressValid && st->address == 0);
    }

    // ---- Several scattered copies of the stub -> all collected -------------------
    {
        std::vector<uint8_t> blob;
        std::vector<size_t>  offs;
        auto pad = [&](size_t n) { for (size_t i = 0; i < n; ++i) blob.push_back((uint8_t)(i * 7 + 1)); };
        auto put = [&]() { offs.push_back(blob.size()); for (uint8_t b : kStub) blob.push_back(b); };

        pad(10); put(); pad(13); put(); pad(8); put(); pad(9);

        BinaryFile bf;
        CHECK(loadBlob(bf, blob, base));
        auto caps = ScanCapabilities(bf);
        const Capability* st = find(caps, kStubName);
        CHECK(st != nullptr);
        if (st) {
            CHECK(st->hitCount == 3);
            CHECK(st->addresses.size() == 3);
            CHECK(st->addressValid);
            CHECK(!st->addresses.empty() && st->address == st->addresses.front());
            for (size_t i = 0; i < offs.size() && i < st->addresses.size(); ++i)
                CHECK(st->addresses[i] == base + offs[i]);
            CHECK(st->detail.find("3 occurrences") != std::string::npos);
        }
    }

    // ---- Single occurrence: hitCount==1, no "(N occurrences)" tail ---------------
    {
        std::vector<uint8_t> blob(40, 0x00);
        for (int i = 0; i < 10; ++i) blob[8 + i] = kStub[i];
        BinaryFile bf;
        CHECK(loadBlob(bf, blob, base));
        auto caps = ScanCapabilities(bf);
        const Capability* st = find(caps, kStubName);
        CHECK(st != nullptr);
        if (st) {
            CHECK(st->hitCount == 1);
            CHECK(st->addresses.size() == 1);
            CHECK(st->address == base + 8);
            CHECK(st->detail.find("occurrences") == std::string::npos);
        }
    }

    // ---- Cap behaviour: more than kMaxPatternHits (64) copies -> capped ----------
    {
        std::vector<uint8_t> blob;
        const int copies = 80;                 // > the 64 cap
        for (int k = 0; k < copies; ++k) {
            for (uint8_t b : kStub) blob.push_back(b);
            blob.push_back(0xEE);              // separator so copies don't merge
        }
        BinaryFile bf;
        CHECK(loadBlob(bf, blob, base));
        auto caps = ScanCapabilities(bf);
        const Capability* st = find(caps, kStubName);
        CHECK(st != nullptr);
        if (st) {
            CHECK(st->hitCount == 64);
            CHECK(st->addresses.size() == 64);
            CHECK(st->detail.find("64+ occurrences") != std::string::npos);
        }
    }

    // ---- Clean blob: no syscall stub present ------------------------------------
    {
        std::vector<uint8_t> blob(256);
        for (size_t i = 0; i < blob.size(); ++i) blob[i] = (uint8_t)(i ^ 0x5A);
        BinaryFile bf;
        CHECK(loadBlob(bf, blob, base));
        auto caps = ScanCapabilities(bf);
        CHECK(find(caps, kStubName) == nullptr);
        // ...and no fabricated "java" capability on a clean blob either.
        for (const auto& c : caps) CHECK(c.category != "java");
    }

    // ---- Exact DLL-aware network imports: UI names must not become sockets -------
    {
        BinaryFile bf;
        const auto pe = importFixturePe({
            { "USER32.dll", { "SendMessageW" } },
            { "KERNEL32.dll", { "ConnectNamedPipeW" } },
        });
        CHECK(loadPe(bf, pe, "techscan_non_network_imports.exe"));
        const auto caps = ScanCapabilities(bf);
        size_t networkCount = 0;
        for (const Capability& capability : caps)
            if (capability.category == "network") ++networkCount;
        CHECK(networkCount == 0);
    }

    // ---- One real WinHTTP trail folds into one staged network capability --------
    {
        BinaryFile bf;
        const auto pe = importFixturePe({
            { "WINHTTP.dll", { "WinHttpConnect", "WinHttpSendRequest",
                                "WinHttpReceiveResponse" } },
        });
        CHECK(loadPe(bf, pe, "techscan_winhttp_imports.exe"));
        const auto caps = ScanCapabilities(bf);
        const Capability* network = nullptr;
        size_t networkCount = 0;
        for (const Capability& capability : caps) {
            if (capability.category != "network") continue;
            network = &capability;
            ++networkCount;
        }
        CHECK(networkCount == 1);
        CHECK(network != nullptr);
        if (network) {
            CHECK(network->detail.find("WinHttpConnect") != std::string::npos);
            CHECK(network->detail.find("WinHttpSendRequest") != std::string::npos);
            CHECK(network->detail.find("WinHttpReceiveResponse") != std::string::npos);
            CHECK(network->addressValid);
        }
    }

    // ---- Java launcher: PE with an appended JAR -> a "java" capability -----------
    {
        // Minimal PE32 (same shape as binaryfile_pe_va_test) + a tiny stored-entry
        // JAR (local header + central directory + EOCD) appended as overlay.
        std::vector<uint8_t> b(0x600, 0);
        auto put16 = [&](size_t off, uint16_t v) { std::memcpy(b.data() + off, &v, 2); };
        auto put32 = [&](size_t off, uint32_t v) { std::memcpy(b.data() + off, &v, 4); };
        b[0] = 'M'; b[1] = 'Z';
        put32(0x3C, 0x80); put32(0x80, 0x00004550);
        const size_t coff = 0x84;
        put16(coff + 0, 0x014C); put16(coff + 2, 1); put16(coff + 16, 0xE0); put16(coff + 18, 0x102);
        const size_t opt = coff + 20;
        put16(opt + 0, 0x10B); put32(opt + 16, 0x1000); put32(opt + 28, 0x400000);
        put32(opt + 32, 0x1000); put32(opt + 36, 0x200); put32(opt + 56, 0x2000);
        put32(opt + 60, 0x400); put32(opt + 92, 16);
        const size_t sec = opt + 0xE0;
        std::memcpy(b.data() + sec, ".text\0\0\0", 8);
        put32(sec + 8, 0x1000); put32(sec + 12, 0x1000); put32(sec + 16, 0x200);
        put32(sec + 20, 0x400); put32(sec + 36, 0x60000020u);

        auto a16 = [&](uint16_t v) { size_t o = b.size(); b.resize(o + 2); put16(o, v); };
        auto a32 = [&](uint32_t v) { size_t o = b.size(); b.resize(o + 4); put32(o, v); };
        auto aS  = [&](const std::string& s) { b.insert(b.end(), s.begin(), s.end()); };
        const std::string nm = "META-INF/MANIFEST.MF";
        const std::string mf = "Manifest-Version: 1.0\r\nMain-Class: a.B\r\n\r\n";
        const uint32_t zipBase = (uint32_t)b.size();              // 0x600
        a32(0x04034b50); a16(20); a16(0); a16(0); a16(0); a16(0); a32(0);
        a32((uint32_t)mf.size()); a32((uint32_t)mf.size()); a16((uint16_t)nm.size()); a16(0);
        aS(nm); aS(mf);
        const uint32_t cdOff = (uint32_t)b.size() - zipBase;
        a32(0x02014b50); a16(20); a16(20); a16(0); a16(0); a16(0); a16(0); a32(0);
        a32((uint32_t)mf.size()); a32((uint32_t)mf.size()); a16((uint16_t)nm.size());
        a16(0); a16(0); a16(0); a16(0); a32(0); a32(0);
        aS(nm);
        const uint32_t cdSize = (uint32_t)b.size() - zipBase - cdOff;
        a32(0x06054b50); a16(0); a16(0); a16(1); a16(1); a32(cdSize); a32(cdOff); a16(0);

        const std::string tmp = "techscan_java.bin";
        { std::ofstream f(tmp, std::ios::binary); f.write((const char*)b.data(), (std::streamsize)b.size()); }
        BinaryFile bf;
        CHECK(bf.load(tmp));
        std::remove(tmp.c_str());
        auto caps = ScanCapabilities(bf);
        const Capability* jc = nullptr;
        for (const auto& c : caps) if (c.category == "java") jc = &c;
        CHECK(jc != nullptr);
        if (jc) {
            CHECK(jc->name.find("Java launcher") != std::string::npos);
            CHECK(jc->confidence > 0.7f);
            CHECK(!jc->detail.empty());
        }
    }

    if (g_fail == 0) std::printf("ALL TECHSCAN MULTI TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
