//
// project_synth_test.cpp
// Round-trip test for the F1/F2 project-sidecar additions (PjSynthesis + PjHotPatch)
// in src/Core/Project.cpp — Serialize -> Deserialize preserves every field.
//
//   cl /std:c++20 /EHsc /I src tests\project_synth_test.cpp src\Core\Project.cpp src\Core\Json.cpp
//   .\project_synth_test.exe
//
#include "Core/Project.h"

#include <cstdio>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    ProjectState st;
    st.hash = 0xDEADBEEFCAFEull;
    st.binaryPath = "x.exe";

    PjSynthesis s;
    s.address = 0x401000; s.size = 16;
    s.pseudoC = "rax = (* v0:64 0x2:64);";
    s.samplesPassed = 256; s.samplesTotal = 256; s.z3Equivalent = true;
    s.reasoning = "I/O-equivalent on 256/256 samples";
    st.syntheses.push_back(s);

    PjHotPatch h{ 0x401100, "c", "int hot(int a){ return a + 1; }" };
    st.hotPatches.push_back(h);

    CHECK(st.hasContent());

    std::string txt = SerializeProject(st);
    ProjectState got;
    CHECK(DeserializeProject(txt, got));

    CHECK(got.syntheses.size() == 1);
    if (got.syntheses.size() == 1) {
        const auto& g = got.syntheses[0];
        CHECK(g.address == 0x401000);
        CHECK(g.size == 16);
        CHECK(g.pseudoC == s.pseudoC);
        CHECK(g.samplesPassed == 256 && g.samplesTotal == 256);
        CHECK(g.z3Equivalent == true);
        CHECK(g.reasoning == s.reasoning);
    }
    CHECK(got.hotPatches.size() == 1);
    if (got.hotPatches.size() == 1) {
        CHECK(got.hotPatches[0].address == 0x401100);
        CHECK(got.hotPatches[0].lang == "c");
        CHECK(got.hotPatches[0].source == h.source);
    }

    // 64-bit address precision preserved through the hex-string encoding.
    CHECK(got.hash == 0xDEADBEEFCAFEull);

    if (g_fail == 0) std::printf("ALL PROJECT-SYNTH TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
