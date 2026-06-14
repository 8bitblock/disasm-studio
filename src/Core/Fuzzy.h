#pragma once
//
// Fuzzy.h
// Tiny case-sensitive subsequence scorer for the command palette (callers pass
// pre-lowercased strings). Pure and dependency-free so it unit-tests with cl
// (tests/fuzzy_test.cpp). Higher score = better match; -1 = needle is not a
// subsequence of the haystack.
//
// Scoring (greedy left-to-right, one pass):
//   +16  needle char matches at haystack index 0
//   +12  match adjacent to the previous match (consecutive run)
//   +12  match right after a word boundary ( _ . : / \ space - )
//   +2   any other match
//   -1   per skipped haystack char between matches (gap penalty, floor 0 bonus)
// Consecutive runs rank as high as boundary hops so an exact prefix always
// beats a scattered match. An empty needle scores 0 (matches everything).
//
#include <cstddef>

namespace ds {

inline int FuzzyScore(const char* needle, const char* hay) {
    if (!needle || !hay) return -1;
    if (!needle[0]) return 0;
    int score = 0;
    size_t h = 0, lastMatch = (size_t)-1;
    auto isBoundary = [](char c) {
        return c == '_' || c == '.' || c == ':' || c == '/' || c == '\\' || c == ' ' || c == '-';
    };
    for (size_t n = 0; needle[n]; ++n) {
        const char want = needle[n];
        size_t start = h;
        while (hay[h] && hay[h] != want) ++h;
        if (!hay[h]) return -1;                    // ran out: not a subsequence
        int bonus;
        if (h == 0)                                              bonus = 16;
        else if (lastMatch != (size_t)-1 && h == lastMatch + 1)  bonus = 12;
        else if (isBoundary(hay[h - 1]))                         bonus = 12;
        else                                                     bonus = 2;
        int gap = (int)(h - start);                // chars skipped to reach this match
        if (gap > bonus - 1) gap = bonus - 1;      // a match never goes net-negative
        score += bonus - gap;
        lastMatch = h;
        ++h;
    }
    return score;
}

} // namespace ds
