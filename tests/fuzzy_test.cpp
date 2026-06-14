// fuzzy_test.cpp
// Unit tests for the command palette's subsequence scorer (Core/Fuzzy.h).
// Build:  cl /std:c++20 /EHsc /I src tests\fuzzy_test.cpp
#include "Core/Fuzzy.h"
#include <cstdio>

static int g_failed = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);      \
            ++g_failed;                                                      \
        }                                                                    \
    } while (0)

int main() {
    using ds::FuzzyScore;

    // Non-matches.
    CHECK(FuzzyScore("xyz", "open binary") == -1);
    CHECK(FuzzyScore("ob", "") == -1);
    CHECK(FuzzyScore("openx", "open") == -1);            // needle longer than matches
    CHECK(FuzzyScore(nullptr, "abc") == -1);
    CHECK(FuzzyScore("a", nullptr) == -1);

    // Trivial matches.
    CHECK(FuzzyScore("", "anything") == 0);              // empty needle matches, lowest rank
    CHECK(FuzzyScore("abc", "abc") > 0);

    // Subsequence (non-contiguous) matches.
    CHECK(FuzzyScore("ob", "open binary") > 0);
    CHECK(FuzzyScore("kernel.createfile", "kernel32.createfilew") > 0);

    // Exact prefix beats a scattered match of the same needle.
    CHECK(FuzzyScore("open", "open binary") > FuzzyScore("open", "o-p-e-n scattered"));

    // A word-boundary match ("bin" at the start of the second word) beats a
    // mid-word match of the same needle.
    CHECK(FuzzyScore("bin", "open binary") > FuzzyScore("bin", "carbine"));

    // Start-of-string beats mid-string for the same needle.
    CHECK(FuzzyScore("save", "save binary as") > FuzzyScore("save", "auto-save binary"));

    // Consecutive runs beat gappy matches.
    CHECK(FuzzyScore("createfile", "createfilew") > FuzzyScore("createfile", "create_a_file_thing"));

    // Boundary chars recognized: _ . : / \ space -
    CHECK(FuzzyScore("f", "mod.func") > FuzzyScore("f", "stuf"));
    CHECK(FuzzyScore("f", "a_func") > FuzzyScore("f", "stuf"));

    // Longer needles accumulate score (sanity: monotone-ish growth on clean prefixes).
    CHECK(FuzzyScore("openbin", "open binary") > FuzzyScore("ob", "open binary"));

    if (g_failed) { std::printf("%d check(s) FAILED\n", g_failed); return 1; }
    std::printf("fuzzy_test: all checks passed\n");
    return 0;
}
