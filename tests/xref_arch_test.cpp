//
// xref_arch_test.cpp
// End-to-end check that the cross-reference sweep (BuildXrefInto) recovers branch
// targets and data references correctly with the REAL Zydis decoder in BOTH x86
// (32-bit) and x64 (64-bit) modes - i.e. the Xrefs feature works for both arches.
//
// Build & run (Windows VS Dev Shell, from project root):
//   set V=vcpkg_installed\x64-windows-static\x64-windows-static
//   cl /nologo /std:c++20 /EHsc /MT /I src /I %V%\include ^
//      tests\xref_arch_test.cpp src\Core\XrefIndex.cpp src\Disasm\ZydisDisassembler.cpp ^
//      %V%\lib\Zydis.lib %V%\lib\Zycore.lib
//   .\xref_arch_test.exe
//
#include "Core/XrefIndex.h"
#include "Disasm/ZydisDisassembler.h"

#include <cstdio>

using namespace ds;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)

int main() {
    // ---- x64: relative call + RIP-relative data load --------------------------
    {
        ZydisDisassembler dis(Arch::X64);
        // 0x1000: E8 1B 00 00 00       call 0x1020         (0x1000 + 5 + 0x1B)
        // 0x1005: 48 8B 05 10 00 00 00 mov rax,[rip+0x10] -> abs 0x1005+7+0x10 = 0x101C
        uint8_t code[] = { 0xE8,0x1B,0x00,0x00,0x00,  0x48,0x8B,0x05,0x10,0x00,0x00,0x00 };
        XrefIndex idx; BuildXrefInto(idx, code, sizeof(code), 0x1000, dis); FinalizeXrefIndex(idx);

        const auto* call = idx.sources(0x1020);
        CHECK(call && call->size() == 1 && (*call)[0] == 0x1000);
        const auto* data = idx.sources(0x1005 + 7 + 0x10);   // RIP-relative resolved to absolute
        CHECK(data && data->size() == 1 && (*data)[0] == 0x1005);
    }

    // ---- x86: relative call + absolute (moffs32) data load --------------------
    {
        ZydisDisassembler dis(Arch::X86);
        // 0x401000: E8 1B 00 00 00   call 0x401020
        // 0x401005: A1 00 20 40 00   mov eax,[0x402000]   (32-bit absolute moffs)
        uint8_t code[] = { 0xE8,0x1B,0x00,0x00,0x00,  0xA1,0x00,0x20,0x40,0x00 };
        XrefIndex idx; BuildXrefInto(idx, code, sizeof(code), 0x401000, dis); FinalizeXrefIndex(idx);

        const auto* call = idx.sources(0x401020);
        CHECK(call && call->size() == 1 && (*call)[0] == 0x401000);
        const auto* data = idx.sources(0x402000);
        CHECK(data && data->size() == 1 && (*data)[0] == 0x401005);
    }

    // ---- arch sensitivity: identical bytes, different meaning -----------------
    // 8B 05 00 20 40 00 == "mov eax,[rip+0x402000]" in x64 but "mov eax,[0x402000]"
    // in x86 (ModRM mod=00 r/m=101). The sweep must follow the decoder's arch.
    {
        uint8_t code[] = { 0x8B,0x05,0x00,0x20,0x40,0x00 };
        ZydisDisassembler x86(Arch::X86), x64(Arch::X64);
        XrefIndex ix86; BuildXrefInto(ix86, code, sizeof(code), 0x401000, x86); FinalizeXrefIndex(ix86);
        XrefIndex ix64; BuildXrefInto(ix64, code, sizeof(code), 0x1000,   x64); FinalizeXrefIndex(ix64);
        CHECK(ix86.sources(0x402000) != nullptr);                 // absolute
        CHECK(ix64.sources(0x1000 + 6 + 0x402000) != nullptr);    // RIP-relative
    }

    if (g_fail) { std::printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("xref_arch_test: all checks passed (x86 + x64)\n");
    return 0;
}
