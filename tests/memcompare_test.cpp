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
#include "Core/Debugger.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <type_traits>

using namespace ds;

static_assert(std::is_same_v<
    decltype(&Debugger::duplicateProcessHandleForSession),
    void* (Debugger::*)(DebugTargetIdentity)>);
static_assert(std::is_same_v<
    decltype(&Debugger::setRegisterForSession),
    bool (Debugger::*)(uint32_t, uint64_t, const std::string&, uint64_t)>);

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

    // ---- strict mutation-input parsing ------------------------------------
    {
        uint64_t bits = 0;
        size_t size = 0;
        CHECK(MemParseValue(B, "255", false, bits, size) && bits == 255 && size == 1);
        CHECK(MemParseValue(B, "-128", false, bits, size) && bits == 0x80 && size == 1);
        CHECK(!MemParseValue(B, "256", false, bits, size));
        CHECK(!MemParseValue(B, "-129", false, bits, size));
        CHECK(MemParseValue(B, "ff", true, bits, size) && bits == 0xFF);
        CHECK(!MemParseValue(B, "100", true, bits, size));
        CHECK(!MemParseValue(D, "12junk", false, bits, size));
        CHECK(!MemParseValue(D, "", false, bits, size));
        CHECK(MemParseValue(Q, "18446744073709551615", false, bits, size) &&
              bits == UINT64_MAX && size == 8);
        CHECK(!MemParseValue(Q, "18446744073709551616", false, bits, size));
        CHECK(MemParseValue(Q, "-9223372036854775808", false, bits, size) &&
              bits == 0x8000000000000000ull);
        CHECK(MemParseValue(F, " 1.25 ", false, bits, size) &&
              bits == bitsF(1.25f) && size == 4);
        CHECK(MemParseValue(DB, "-2.5", false, bits, size) &&
              bits == bitsD(-2.5) && size == 8);
        CHECK(!MemParseValue(F, "3.5f", false, bits, size));
        CHECK(!MemParseValue(F, "nan", false, bits, size));
        CHECK(!MemParseValue(DB, "inf", false, bits, size));
        CHECK(!MemParseValue(DB, "1e9999", false, bits, size));

        uint64_t address = 0xDEADBEEF;
        CHECK(MemParseHexAddress("0", address) && address == 0);
        CHECK(MemParseHexAddress("0x0", address) && address == 0);
        CHECK(MemParseHexAddress("  000  ", address) && address == 0);
        CHECK(MemParseHexAddress("7fffFFFF", address) && address == 0x7FFFFFFF);
        address = 0xDEADBEEF;
        CHECK(!MemParseHexAddress("", address) && address == 0xDEADBEEF);
        CHECK(!MemParseHexAddress("xyz", address) && address == 0xDEADBEEF);
        CHECK(!MemParseHexAddress("10junk", address) && address == 0xDEADBEEF);
        CHECK(!MemParseHexAddress("-0", address) && address == 0xDEADBEEF);
        CHECK(!MemParseHexAddress("10000000000000000", address) && address == 0xDEADBEEF);
    }

    // The address-table master switch is authoritative: leaving Freeze checked
    // while disabling a row must not continue writing into the target process.
    CHECK(MemAddressTableShouldWrite(true, true, true));
    CHECK(!MemAddressTableShouldWrite(true, false, true));
    CHECK(!MemAddressTableShouldWrite(true, true, false));
    CHECK(!MemAddressTableShouldWrite(false, true, true));
    CHECK(MemAddressTableShouldWrite(true, true, true, 7, 1234, 7, 1234));
    CHECK(!MemAddressTableShouldWrite(true, true, true, 8, 1234, 7, 1234));
    CHECK(!MemAddressTableShouldWrite(true, true, true, 7, 5678, 7, 1234));
    CHECK(!MemAddressTableShouldWrite(true, true, true, 0, 1234, 0, 1234));
    CHECK(!MemAddressTableShouldWrite(true, true, true, 7, 0, 7, 0));

    // The same pure predicate is used inside Debugger::readMemoryForSession and
    // writeMemoryForSession while hProcMtx_ remains held through the actual OS
    // operation. Exercise detach/reattach ABA cases without a live debuggee.
    constexpr DebugTargetIdentity firstAttach{ 4242, 10 };
    constexpr DebugTargetIdentity sameSession{ 4242, 10 };
    constexpr DebugTargetIdentity samePidReattached{ 4242, 11 };
    constexpr DebugTargetIdentity pidReused{ 7777, 10 };
    constexpr DebugTargetIdentity noPublishedHandle{};
    static_assert(DebugTargetIdentityMatches(firstAttach, sameSession));
    static_assert(!DebugTargetIdentityMatches(firstAttach, samePidReattached));
    static_assert(!DebugTargetIdentityMatches(firstAttach, pidReused));
    static_assert(!DebugTargetIdentityMatches(noPublishedHandle, noPublishedHandle));
    CHECK(DebugTargetIdentityMatches(firstAttach, sameSession));
    CHECK(!DebugTargetIdentityMatches(firstAttach, samePidReattached));
    CHECK(!DebugTargetIdentityMatches(firstAttach, pidReused));
    CHECK(!DebugTargetIdentityMatches(noPublishedHandle, firstAttach));

    // A naturally exited target retains its PID/generation in the debugger's
    // post-mortem snapshot, but it is no longer a usable memory session. That
    // state transition must clear scans/frozen rows just like an explicit detach.
    CHECK(MemTargetSessionUsable(true, 7, 1234));
    CHECK(!MemTargetSessionUsable(false, 7, 1234));
    CHECK(MemTargetSessionChanged(false, 7, 1234, true, 7, 1234));
    CHECK(MemTargetSessionChanged(true, 8, 1234, true, 7, 1234));
    CHECK(MemTargetSessionChanged(true, 7, 5678, true, 7, 1234));
    CHECK(!MemTargetSessionChanged(true, 7, 1234, true, 7, 1234));

    if (g_fail == 0) std::printf("ALL MEMCOMPARE TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
