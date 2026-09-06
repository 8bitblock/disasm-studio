//
// algoscan_test.cpp
// Off-target test for src/Core/AlgoScan.cpp (the FindCrypt/capa-style algorithm
// recognizer): known constant-table detection, BE/LE orientation reporting, the
// XrefIndex -> referencing-function extent mapping, and the Base64 alphabet
// classifier (standard / mutated, plus the false-positive gate).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\algoscan_test.cpp ^
//       src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp
//   .\algoscan_test.exe
// (g++: g++ -std=c++20 -I src tests/algoscan_test.cpp \
//       src/Core/AlgoScan.cpp src/Core/SigMatch.cpp src/Core/BinaryFile.cpp -o algoscan_test)
//
#include "Core/AlgoScan.h"
#include "Core/BinaryFile.h"
#include "Core/XrefIndex.h"
#include "Core/AnalysisJobs.h"   // FuncResult

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

static const uint8_t kAesSbox16[16] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76 };
// SHA-256 K[0..3] = {428A2F98, 71374491, B5C0FBCF, E9B5DBA5}
static const uint8_t kSha256BE[16] = {
    0x42,0x8A,0x2F,0x98, 0x71,0x37,0x44,0x91, 0xB5,0xC0,0xFB,0xCF, 0xE9,0xB5,0xDB,0xA5 };
static const uint8_t kSha256LE[16] = {
    0x98,0x2F,0x8A,0x42, 0x91,0x44,0x37,0x71, 0xCF,0xFB,0xC0,0xB5, 0xA5,0xDB,0xB5,0xE9 };

static const char* const kB64Std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const AlgoMatch* find(const std::vector<AlgoMatch>& v, const char* name) {
    for (const auto& m : v) if (m.name == name) return &m;
    return nullptr;
}
static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }

// Write `bytes` to a temp file and loadRaw it at `base` (Raw -> no sections, whole-image
// scan; imageBase() == base so a hit at offset off reports VA base+off).
static bool loadBlob(BinaryFile& bf, const std::vector<uint8_t>& bytes, uint64_t base) {
    char tmp[L_tmpnam_s]; if (tmpnam_s(tmp, sizeof(tmp)) != 0) return false;
    std::string path = std::string(tmp);
    { std::ofstream f(path, std::ios::binary); f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
    bool ok = bf.loadRaw(path, base);
    std::remove(path.c_str());
    return ok;
}

static void put16(std::vector<uint8_t>& b, size_t off, uint16_t value) {
    std::memcpy(b.data() + off, &value, sizeof(value));
}
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t value) {
    std::memcpy(b.data() + off, &value, sizeof(value));
}

// One all-executable PE section whose raw offset differs from its RVA, followed
// by an overlay. This pins structured FILE-offset versus VA authority.
static std::vector<uint8_t> buildAllExecPe() {
    std::vector<uint8_t> bytes(0x700, 0);
    bytes[0] = 'M'; bytes[1] = 'Z'; put32(bytes, 0x3c, 0x80);
    put32(bytes, 0x80, 0x00004550);
    const size_t coff = 0x84, opt = coff + 20, sec = opt + 0xe0;
    put16(bytes, coff, 0x014c); put16(bytes, coff + 2, 1);
    put16(bytes, coff + 16, 0xe0); put16(bytes, coff + 18, 0x0102);
    put16(bytes, opt, 0x10b); put32(bytes, opt + 16, 0);
    put32(bytes, opt + 28, 0x400000); put32(bytes, opt + 32, 0x1000);
    put32(bytes, opt + 36, 0x200); put32(bytes, opt + 56, 0x2000);
    put32(bytes, opt + 60, 0x400); put32(bytes, opt + 92, 16);
    std::memcpy(bytes.data() + sec, ".text", 5);
    put32(bytes, sec + 8, 0x200); put32(bytes, sec + 12, 0x1000);
    put32(bytes, sec + 16, 0x200); put32(bytes, sec + 20, 0x400);
    put32(bytes, sec + 36, 0x60000020u);
    std::memcpy(bytes.data() + 0x420, kB64Std, 64); // mapped: VA 0x401020
    std::memcpy(bytes.data() + 0x620, kB64Std, 64); // overlay: no VA
    return bytes;
}

static bool loadStructured(BinaryFile& bf, const std::vector<uint8_t>& bytes) {
    char tmp[L_tmpnam_s]; if (tmpnam_s(tmp, sizeof(tmp)) != 0) return false;
    const std::string path(tmp);
    { std::ofstream f(path, std::ios::binary); f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
    const bool ok = bf.load(path);
    std::remove(path.c_str());
    return ok;
}

int main() {
    const uint64_t base = 0x400000;

    // Primary evidence at VA zero is valid and must not be confused with no hit.
    {
        std::vector<uint8_t> blob;
        for (int i = 0; i < 64; ++i) blob.push_back((uint8_t)kB64Std[i]);
        BinaryFile bf;
        CHECK(loadBlob(bf, blob, 0));
        const std::vector<AlgoMatch> matches = ScanAlgorithms(bf);
        const AlgoMatch* match = find(matches, "Base64 (standard alphabet)");
        CHECK(match != nullptr);
        if (match) CHECK(match->addressValid && match->address == 0);
    }

    // ---- 1) Constant detection + extent mapping ----------------------------------
    {
        std::vector<uint8_t> blob;
        auto pad = [&](size_t n) { for (size_t i = 0; i < n; ++i) blob.push_back((uint8_t)(i * 7 + 1)); };
        pad(16);
        size_t aesOff = blob.size(); for (uint8_t b : kAesSbox16) blob.push_back(b);
        pad(16);
        size_t shaOff = blob.size(); for (uint8_t b : kSha256BE) blob.push_back(b);
        pad(16);

        BinaryFile bf;
        CHECK(loadBlob(bf, blob, base));

        // Hand-built xref: the AES table is referenced by an instruction at base+0x100,
        // which lives inside function sub_F0 [base+0xF0, +0x40).
        XrefIndex xi;
        xi.toTarget[base + aesOff] = { base + 0x100 };
        std::vector<FuncResult> funcs;
        FuncResult f; f.address = base + 0xF0; f.size = 0x40; f.name = "sub_F0"; funcs.push_back(f);

        auto ms = ScanAlgorithms(bf, &xi, &funcs);
        const AlgoMatch* aes = find(ms, "AES Rijndael S-box");
        const AlgoMatch* sha = find(ms, "SHA-256 K[64]");
        CHECK(aes != nullptr);
        CHECK(sha != nullptr);
        if (aes) {
            CHECK(!aes->dataVAs.empty() && aes->dataVAs.front() == base + aesOff);
            CHECK(aes->address == base + aesOff);
            CHECK(aes->kind == AlgoKind::ConstantTable);
            CHECK(aes->referencedBy.size() == 1);
            if (aes->referencedBy.size() == 1) {
                CHECK(aes->referencedBy[0].funcAddress == base + 0xF0);
                CHECK(aes->referencedBy[0].funcName == "sub_F0");
                CHECK(aes->referencedBy[0].refInsn == base + 0x100);
            }
        }
        if (sha) {
            CHECK(!sha->dataVAs.empty() && sha->dataVAs.front() == base + shaOff);
            CHECK(has(sha->detail, "big-endian"));
            CHECK(sha->referencedBy.empty());   // no xref entry for the SHA table
        }
    }

    // ---- 2) Orientation: same constant in BE and LE both detected, both noted -----
    {
        std::vector<uint8_t> blob;
        auto pad = [&](size_t n) { for (size_t i = 0; i < n; ++i) blob.push_back((uint8_t)(i * 3 + 2)); };
        pad(8); for (uint8_t b : kSha256BE) blob.push_back(b);
        pad(8); for (uint8_t b : kSha256LE) blob.push_back(b);
        pad(8);

        BinaryFile bf;
        CHECK(loadBlob(bf, blob, base));
        auto ms = ScanAlgorithms(bf);
        const AlgoMatch* sha = find(ms, "SHA-256 K[64]");
        CHECK(sha != nullptr);
        if (sha) {
            CHECK(sha->dataVAs.size() == 2);
            CHECK(has(sha->detail, "big-endian"));
            CHECK(has(sha->detail, "little-endian"));
        }
    }

    // ---- 3) Base64 standard alphabet ---------------------------------------------
    {
        std::vector<uint8_t> blob(16, 0x00);
        for (int i = 0; i < 64; ++i) blob.push_back((uint8_t)kB64Std[i]);
        blob.insert(blob.end(), 16, 0x00);
        BinaryFile bf;
        CHECK(loadBlob(bf, blob, base));
        auto ms = ScanAlgorithms(bf);
        const AlgoMatch* a = find(ms, "Base64 (standard alphabet)");
        CHECK(a != nullptr);
        if (a) {
            CHECK(a->kind == AlgoKind::AlphabetStd);
            CHECK(a->address == base + 16);
            CHECK(a->alphabet == std::string(kB64Std, 64));
            CHECK(a->substitutionNote.empty());
        }
        CHECK(find(ms, "Base64 (mutated alphabet)") == nullptr);
    }

    // ---- 4) Base64 mutated alphabet + the false-positive negative ----------------
    {
        // Mutated: swap the first two symbols of the standard alphabet (a permutation).
        std::vector<uint8_t> mut;
        for (int i = 0; i < 64; ++i) mut.push_back((uint8_t)kB64Std[i]);
        std::swap(mut[0], mut[1]);

        std::vector<uint8_t> blob(8, 0x11);
        blob.insert(blob.end(), mut.begin(), mut.end());
        blob.insert(blob.end(), 8, 0x11);
        BinaryFile bf;
        CHECK(loadBlob(bf, blob, base));
        auto ms = ScanAlgorithms(bf);
        const AlgoMatch* a = find(ms, "Base64 (mutated alphabet)");
        CHECK(a != nullptr);
        if (a) {
            CHECK(a->kind == AlgoKind::AlphabetMutated);
            CHECK(a->alphabet == std::string((const char*)mut.data(), 64));
            CHECK(has(a->substitutionNote, "2 of 64"));
        }
        CHECK(find(ms, "Base64 (standard alphabet)") == nullptr);

        // Negative: 64 distinct printable bytes ('!'..'`') that are NOT the Base64 set.
        std::vector<uint8_t> neg(8, 0x22);
        for (int c = 0x21; c <= 0x60; ++c) neg.push_back((uint8_t)c);   // 64 distinct printables
        neg.insert(neg.end(), 8, 0x22);
        BinaryFile bf2;
        CHECK(loadBlob(bf2, neg, base));
        auto ms2 = ScanAlgorithms(bf2);
        CHECK(find(ms2, "Base64 (mutated alphabet)") == nullptr);
        CHECK(find(ms2, "Base64 (standard alphabet)") == nullptr);
    }

    // ---- 5) Structured all-executable image: mapped section VAs only --------------
    {
        BinaryFile bf;
        CHECK(loadStructured(bf, buildAllExecPe()));
        const auto matches = ScanAlgorithms(bf);
        size_t standardCount = 0;
        const AlgoMatch* standard = nullptr;
        for (const AlgoMatch& match : matches) {
            if (match.name != "Base64 (standard alphabet)") continue;
            ++standardCount;
            standard = &match;
        }
        CHECK(standardCount == 1);
        if (standard)
            CHECK(standard->addressValid && standard->address == 0x401020);
    }

    // ---- 6) Clean blob: none of the headline signatures present ------------------
    {
        std::vector<uint8_t> blob(512);
        for (size_t i = 0; i < blob.size(); ++i) blob[i] = (uint8_t)(i ^ 0x5A);
        BinaryFile bf;
        CHECK(loadBlob(bf, blob, base));
        auto ms = ScanAlgorithms(bf);
        CHECK(find(ms, "AES Rijndael S-box") == nullptr);
        CHECK(find(ms, "SHA-256 K[64]") == nullptr);
        CHECK(find(ms, "MD5 T-table") == nullptr);
        CHECK(find(ms, "Base64 (standard alphabet)") == nullptr);
    }

    if (g_fail == 0) std::printf("ALL ALGOSCAN TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
