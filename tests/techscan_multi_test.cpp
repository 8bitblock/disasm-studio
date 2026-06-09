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
//       src\Core\TechScan.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp
//   .\techscan_multi_test.exe
//
#include "Core/TechScan.h"
#include "Core/BinaryFile.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

int main() {
    const uint64_t base = 0x400000;

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
    }

    if (g_fail == 0) std::printf("ALL TECHSCAN MULTI TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
