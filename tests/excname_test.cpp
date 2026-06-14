//
// excname_test.cpp
// Tests for src/Core/ExcName.h: the exception-code -> semantic-name map used by
// the debug toolbar / Breakpoints tab labels.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\excname_test.cpp
//   .\excname_test.exe
//
#include "Core/ExcName.h"
#include <cstdio>
#include <cstring>
#include <string>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    // Known codes resolve to the standard names.
    CHECK(std::strcmp(ExceptionCodeName(0xC0000005u), "ACCESS_VIOLATION") == 0);
    CHECK(std::strcmp(ExceptionCodeName(0x80000003u), "BREAKPOINT") == 0);
    CHECK(std::strcmp(ExceptionCodeName(0x80000004u), "SINGLE_STEP") == 0);
    CHECK(std::strcmp(ExceptionCodeName(0xC0000094u), "INT_DIVIDE_BY_ZERO") == 0);
    CHECK(std::strcmp(ExceptionCodeName(0xC000001Du), "ILLEGAL_INSTRUCTION") == 0);
    CHECK(std::strcmp(ExceptionCodeName(0xC00000FDu), "STACK_OVERFLOW") == 0);
    CHECK(std::strcmp(ExceptionCodeName(0xC0000409u), "STACK_BUFFER_OVERRUN") == 0);
    CHECK(std::strcmp(ExceptionCodeName(0xE06D7363u), "CPP_EXCEPTION") == 0);
    CHECK(std::strcmp(ExceptionCodeName(0xE0434352u), "CLR_EXCEPTION") == 0);
    CHECK(std::strcmp(ExceptionCodeName(0x4000001Fu), "WX86_BREAKPOINT") == 0);

    // Unknown codes return null from the name map...
    CHECK(ExceptionCodeName(0x12345678u) == nullptr);
    CHECK(ExceptionCodeName(0) == nullptr);

    // ...and the label helper formats both shapes.
    CHECK(ExceptionCodeLabel(0xC0000005u) == "ACCESS_VIOLATION (0xC0000005)");
    CHECK(ExceptionCodeLabel(0x12345678u) == "exception 0x12345678");

    if (g_fail == 0) std::printf("ALL EXCNAME TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
