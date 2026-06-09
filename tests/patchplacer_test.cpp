//
// patchplacer_test.cpp
// Off-target unit test for the PURE hot-patch placement logic
// (src/Core/PatchPlacer.cpp): code-cave discovery, rel32 JMP encoding, and the
// in-span / detour / needs-alloc / refused placement decisions with exact byte math.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\patchplacer_test.cpp src\Core\PatchPlacer.cpp
//   .\patchplacer_test.exe
//
#include "Core/PatchPlacer.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static bool eqBytes(const std::vector<uint8_t>& a, std::vector<uint8_t> b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) if (a[i] != b[i]) return false;
    return true;
}

static void dump(const char* tag, const std::vector<uint8_t>& v) {
    std::printf("  %s:", tag);
    for (uint8_t b : v) std::printf(" %02X", b);
    std::printf("\n");
}

int main() {
    // ---- FindCodeCaves -----------------------------------------------------
    // region: 4 code bytes, 20x 0xCC, 3 code bytes, 6x 0x00.
    std::vector<uint8_t> region = {
        0x55, 0x8B, 0xEC, 0x90,                                     // code (none are 00/CC)
    };
    for (int i = 0; i < 20; ++i) region.push_back(0xCC);            // cave1: 0xCC x20
    region.push_back(0x55); region.push_back(0x55); region.push_back(0x55);
    for (int i = 0; i < 6; ++i) region.push_back(0x00);            // cave2: 0x00 x6
    const uint64_t baseVA = 0x401000;
    std::vector<ExecRegion> regions = { { baseVA, region.data(), region.size() } };

    {   // minLen 8 -> only the 20-byte 0xCC run qualifies
        auto caves = FindCodeCaves(regions, 8);
        CHECK(caves.size() == 1);
        if (caves.size() == 1) { CHECK(caves[0].va == baseVA + 4); CHECK(caves[0].size == 20); }
    }
    {   // minLen 4 -> both runs qualify, ascending VA
        auto caves = FindCodeCaves(regions, 4);
        CHECK(caves.size() == 2);
        if (caves.size() == 2) {
            CHECK(caves[0].va == baseVA + 4   && caves[0].size == 20);
            CHECK(caves[1].va == baseVA + 27  && caves[1].size == 6);   // 4+20+3 = 27
        }
    }
    {   // avoid an address inside cave1 -> it is excluded
        auto caves = FindCodeCaves(regions, 4, { baseVA + 10 });
        CHECK(caves.size() == 1);
        if (caves.size() == 1) CHECK(caves[0].va == baseVA + 27);
    }

    // ---- MakeRel32Jmp ------------------------------------------------------
    {   // forward: 0x401000 -> 0x402000, rel = 0x1000 - 5 = 0x0FFB
        std::vector<uint8_t> j;
        CHECK(MakeRel32Jmp(0x401000, 0x402000, j));
        CHECK(eqBytes(j, { 0xE9, 0xFB, 0x0F, 0x00, 0x00 }));
    }
    {   // backward: 0x402000 -> 0x401000, rel = -0x1005 = 0xFFFFEFFB
        std::vector<uint8_t> j;
        CHECK(MakeRel32Jmp(0x402000, 0x401000, j));
        CHECK(eqBytes(j, { 0xE9, 0xFB, 0xEF, 0xFF, 0xFF }));
    }
    {   // out of +/-2GB range -> false, out unchanged
        std::vector<uint8_t> j;
        CHECK(!MakeRel32Jmp(0x0, 0x90000000, j));
        CHECK(j.empty());
    }

    // ---- PlacePatch: InSpan ------------------------------------------------
    {
        PlaceInput in;
        in.siteVA = 0x401000;
        in.origLen = 10;
        in.newBody = { 0xB8, 0x01, 0x00, 0x00, 0x00 };   // mov eax,1 (5 bytes)
        PlaceResult r = PlacePatch(in);
        CHECK(r.status == PlaceStatus::InSpan);
        CHECK(r.writes.size() == 1);
        if (r.writes.size() == 1) {
            CHECK(r.writes[0].va == 0x401000);
            CHECK(r.writes[0].origLen == 10);
            CHECK(eqBytes(r.writes[0].bytes,
                  { 0xB8,0x01,0x00,0x00,0x00, 0x90,0x90,0x90,0x90,0x90 }));
        }
    }

    // ---- PlacePatch: Detour into a cave -----------------------------------
    {
        PlaceInput in;
        in.siteVA = 0x401000;
        in.origLen = 6;
        in.newBody.assign(20, 0xAA);                 // 20-byte body
        in.caves = { { 0x402000, 64 } };
        PlaceResult r = PlacePatch(in);
        CHECK(r.status == PlaceStatus::Detour);
        CHECK(r.caveVA == 0x402000);
        CHECK(r.writes.size() == 2);
        if (r.writes.size() == 2) {
            // site: JMP 0x401000 -> 0x402000 (E9 FB 0F 00 00) + 1 NOP (origLen 6)
            CHECK(r.writes[0].va == 0x401000 && r.writes[0].origLen == 6);
            CHECK(eqBytes(r.writes[0].bytes, { 0xE9,0xFB,0x0F,0x00,0x00, 0x90 }));
            // cave: 20x 0xAA + JMP-back 0x402014 -> 0x401006 (rel -0x1013 = FFFFEFED)
            std::vector<uint8_t> expCave(20, 0xAA);
            expCave.insert(expCave.end(), { 0xE9, 0xED, 0xEF, 0xFF, 0xFF });
            CHECK(r.writes[1].va == 0x402000 && r.writes[1].origLen == 25);
            CHECK(eqBytes(r.writes[1].bytes, expCave));
            if (!eqBytes(r.writes[1].bytes, expCave)) dump("got cave", r.writes[1].bytes);
        }
    }

    // ---- PlacePatch: Refused (span too small for a JMP) -------------------
    {
        PlaceInput in;
        in.siteVA = 0x401000; in.origLen = 3;
        in.newBody.assign(20, 0xAA);
        in.caves = { { 0x402000, 64 } };
        PlaceResult r = PlacePatch(in);
        CHECK(r.status == PlaceStatus::Refused);
        CHECK(r.writes.empty());
        CHECK(r.reason.find("JMP detour") != std::string::npos);
    }

    // ---- PlacePatch: NeedsAlloc (no cave, alloc permitted) ----------------
    {
        PlaceInput in;
        in.siteVA = 0x401000; in.origLen = 6;
        in.newBody.assign(20, 0xAA);
        in.allowAlloc = true;                        // no caves provided
        PlaceResult r = PlacePatch(in);
        CHECK(r.status == PlaceStatus::NeedsAlloc);
        CHECK(r.requiredCaveSize == 25);             // 20 body + 5 jmp-back
    }

    // ---- PlacePatch: Refused (no cave, no alloc) --------------------------
    {
        PlaceInput in;
        in.siteVA = 0x401000; in.origLen = 6;
        in.newBody.assign(20, 0xAA);
        PlaceResult r = PlacePatch(in);
        CHECK(r.status == PlaceStatus::Refused);
        CHECK(r.writes.empty());
    }

    // ---- PlacePatch: Detour into a caller-allocated region ----------------
    {
        PlaceInput in;
        in.siteVA = 0x401000; in.origLen = 6;
        in.newBody.assign(20, 0xAA);
        in.allowAlloc = true;
        in.allocVA = 0x50000000;                     // within +/-2GB of the site
        PlaceResult r = PlacePatch(in);
        CHECK(r.status == PlaceStatus::Detour);
        CHECK(r.caveVA == 0x50000000);
        CHECK(r.writes.size() == 2);
    }

    if (g_fail == 0) std::printf("ALL PATCHPLACER TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
