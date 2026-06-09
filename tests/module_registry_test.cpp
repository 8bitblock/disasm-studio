//
// module_registry_test.cpp
// Unit-tests ModuleRegistry: add/update keyed by base, lookups (by base / containing
// VA), active-index tracking, and removal index fix-ups. Pure Core (no ImGui/Win32).
//
// Compile + run (MSVC dev shell), from the repo root:
//   cl /nologo /std:c++20 /EHsc /D_CRT_SECURE_NO_WARNINGS /I src ^
//      tests\module_registry_test.cpp src\Core\BinaryFile.cpp
//
#include "Core/ModuleRegistry.h"

#include <cstdio>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

int main() {
    ModuleRegistry reg;
    CHECK(reg.empty(), "starts empty");
    CHECK(reg.activeIndex() == -1, "no active module initially");

    LoadedModule* exe   = reg.addOrUpdate("app.exe", 0x140000000ull, 0x20000, "C:\\app.exe");
    LoadedModule* ntdll = reg.addOrUpdate("ntdll.dll", 0x7FF800000000ull, 0x200000);
    LoadedModule* k32   = reg.addOrUpdate("kernel32.dll", 0x7FF810000000ull, 0x100000);
    exe->isMain = true;
    CHECK(reg.size() == 3, "three modules added");

    // addOrUpdate on an existing base updates, doesn't duplicate.
    LoadedModule* again = reg.addOrUpdate("ntdll.dll", 0x7FF800000000ull, 0x210000);
    CHECK(reg.size() == 3, "addOrUpdate of same base does not duplicate");
    CHECK(again == ntdll, "addOrUpdate returns the existing entry");
    CHECK(ntdll->size == 0x210000, "size updated on re-add");

    // Lookups.
    CHECK(reg.byBase(0x7FF810000000ull) == k32, "byBase finds kernel32");
    CHECK(reg.byBase(0xDEADBEEF) == nullptr, "byBase miss returns null");
    CHECK(reg.indexByBase(0x140000000ull) == 0, "indexByBase of exe");
    CHECK(reg.containing(0x140000100ull) == exe, "containing VA inside exe");
    CHECK(reg.containing(0x7FF800001000ull) == ntdll, "containing VA inside ntdll");
    CHECK(reg.containing(0x10) == nullptr, "containing VA outside all modules");

    // analyzed()/contains helpers.
    CHECK(!exe->analyzed(), "module not analyzed before cache populated");
    exe->cache.funcsValid = true;
    CHECK(exe->analyzed(), "module analyzed once funcsValid");
    CHECK(exe->contains(0x140000000ull) && !exe->contains(0x140020000ull), "contains bounds [base, base+size)");

    // Active tracking + removal index fix-ups.
    reg.setActiveByBase(0x7FF810000000ull);   // kernel32 at index 2
    CHECK(reg.activeIndex() == 2 && reg.active() == k32, "active set to kernel32");
    reg.removeByBase(0x140000000ull);          // remove exe (index 0) -> active shifts to 1
    CHECK(reg.size() == 2, "module removed");
    CHECK(reg.activeIndex() == 1 && reg.active() == k32, "active index fixed up after earlier removal");
    reg.removeByBase(0x7FF810000000ull);       // remove the active module
    CHECK(reg.activeIndex() == -1, "active cleared when the active module is removed");

    reg.clear();
    CHECK(reg.empty() && reg.activeIndex() == -1, "clear resets registry");

    if (g_fail == 0) std::printf("module_registry_test: all checks passed\n");
    else             std::printf("module_registry_test: %d FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
