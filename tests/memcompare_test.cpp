//
// memcompare_test.cpp
// Off-target unit test for the PURE numeric interpretation/comparison helper
// (src/Core/MemCompare.h) that backs the Memory Tools scanner's signed vs
// UNSIGNED bigger/smaller comparisons.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\memcompare_test.cpp
//   .\memcompare_test.exe
//
#include "Core/MemCompare.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static uint64_t bitsF(float f)  { uint64_t b = 0; std::memcpy(&b, &f, 4); return b; }
static uint64_t bitsD(double d) { uint64_t b = 0; std::memcpy(&b, &d, 8); return b; }

int main() {
    const int B = (int)MemValType::Byte, W = (int)MemValType::Word,
              D = (int)MemValType::Dword, Q = (int)MemValType::Qword,
              F = (int)MemValType::Float, DB = (int)MemValType::Double;

    // ---- type sizes --------------------------------------------------------
    CHECK(MemTypeSize(B) == 1 && MemTypeSize(W) == 2 && MemTypeSize(D) == 4 &&
          MemTypeSize(Q) == 8 && MemTypeSize(F) == 4 && MemTypeSize(DB) == 8);

    // ---- SIGNED interpretation (default): -1 < 0 ---------------------------
    CHECK(MemAsNumber(B, 0xFF, /*unsigned*/false)        == -1.0);
    CHECK(MemAsNumber(W, 0xFFFF, false)                  == -1.0);
    CHECK(MemAsNumber(D, 0xFFFFFFFFull, false)           == -1.0);
    CHECK(MemAsNumber(Q, (uint64_t)-1, false)            == -1.0);
    CHECK(MemLess(D, false, 0xFFFFFFFFull, 0));          // -1 < 0 signed
    CHECK(!MemGreater(D, false, 0xFFFFFFFFull, 0));

    // ---- UNSIGNED interpretation: 0xFFFFFFFF is huge, > 0 ------------------
    CHECK(MemAsNumber(B, 0xFF, /*unsigned*/true)         == 255.0);
    CHECK(MemAsNumber(W, 0xFFFF, true)                   == 65535.0);
    CHECK(MemAsNumber(D, 0xFFFFFFFFull, true)            == 4294967295.0);
    CHECK(MemGreater(D, true, 0xFFFFFFFFull, 0));        // ~4.29e9 > 0 unsigned
    CHECK(!MemLess(D, true, 0xFFFFFFFFull, 0));

    // The mode flips the ordering of the SAME two bit patterns.
    {
        uint64_t a = 0xFFFFFFFFull;   // signed -1, unsigned ~4.29e9
        uint64_t b = 0x00000001ull;   // 1
        CHECK(MemLess   (D, /*signed*/false, a, b));     // -1 < 1
        CHECK(MemGreater(D, /*unsigned*/true,  a, b));   // 4.29e9 > 1
    }

    // Word boundary: 0x8000 is -32768 signed, 32768 unsigned.
    CHECK(MemAsNumber(W, 0x8000, false) == -32768.0);
    CHECK(MemAsNumber(W, 0x8000, true)  ==  32768.0);

    // Only the low typeSize bytes matter; high garbage bits are ignored.
    CHECK(MemAsNumber(B, 0xDEADBEEFFFull, false) == -1.0);   // low byte 0xFF
    CHECK(MemAsNumber(B, 0xDEADBEEFFFull, true)  == 255.0);

    // ---- qword precision: integers compare as integers, not via double -----
    // Adjacent qwords above 2^53 collapse to the same double; the integer path
    // must still order them correctly.
    {
        uint64_t lo = 0x20000000000000ull;       // 2^53
        uint64_t hi = 0x20000000000001ull;       // 2^53 + 1
        CHECK(MemGreater(Q, true,  hi, lo));
        CHECK(!MemLess  (Q, true,  hi, lo));
        CHECK(MemLess   (Q, true,  lo, hi));
        CHECK(!MemGreater(Q, true, lo, hi));
        CHECK(MemGreater(Q, false, hi, lo));     // both positive signed too
        CHECK(!MemGreater(Q, false, lo, hi));
    }
    // INT64_MIN < 0 signed; max-u64 > 0 unsigned but < 0 signed (-1).
    CHECK(MemLess   (Q, false, 0x8000000000000000ull, 0));
    CHECK(!MemGreater(Q, false, 0x8000000000000000ull, 0));
    CHECK(MemGreater(Q, true,  0xFFFFFFFFFFFFFFFFull, 0));
    CHECK(MemLess   (Q, false, 0xFFFFFFFFFFFFFFFFull, 0));
    // Sub-qword types ignore high garbage bits on the integer path too.
    CHECK(MemLess   (B, false, 0xDEADBEEFFFull, 0));          // low byte 0xFF = -1
    CHECK(MemGreater(B, true,  0xDEADBEEFFFull, 0));          // low byte 0xFF = 255
    // Extension helpers.
    CHECK(MemZeroExt(0xFFFFFFFFFFull, 4) == 0xFFFFFFFFull);
    CHECK(MemSignExt(0x80, 1) == -128);
    CHECK(MemSignExt(0x7F, 1) == 127);
    CHECK(MemSignExt(0xFFFFFFFFFFFFFFFFull, 8) == -1);

    // ---- float / double ignore unsignedMode --------------------------------
    CHECK(MemAsNumber(F, bitsF(-3.5f), false) == -3.5);
    CHECK(MemAsNumber(F, bitsF(-3.5f), true)  == -3.5);      // mode ignored for float
    CHECK(MemAsNumber(DB, bitsD(2.25), true)  ==  2.25);
    CHECK(MemLess(F, true, bitsF(-1.0f), bitsF(0.0f)));      // -1.0 < 0.0 regardless of mode
    CHECK(MemGreater(DB, false, bitsD(10.0), bitsD(9.99)));

    if (g_fail == 0) std::printf("ALL MEMCOMPARE TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
