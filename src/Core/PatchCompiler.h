#pragma once
//
// PatchCompiler.h
// F2 "high-level hot-patch": turn editor source into a position-independent machine-code
// body that PatchPlacer can land. Two tiers:
//   * Asm    — always available (Keystone, already linked). The zero-dep MVP.
//   * C      — vendored libtcc, gated behind DS_HAVE_LIBTCC.
// When a tier's dep is not compiled in, CompilePatch returns ok=false with a clear
// diagnostic, so the app builds and the asm tier still works.
//
#include "../Disasm/IDisassembler.h"   // ds::Arch

#include <cstdint>
#include <string>
#include <vector>

namespace ds {

enum class PatchLang { Asm, C };

struct PatchCtx {
    Arch     arch   = Arch::X64;
    uint64_t siteVA = 0;          // address the body is being assembled for (rel operands)
};

struct CompileResult {
    bool                 ok = false;
    std::vector<uint8_t> bytes;        // the compiled, position-independent body
    std::string          diagnostics;  // assembler/compiler messages (esp. when !ok)
};

const char* PatchLangName(PatchLang l);
bool PatchLanguageAvailable(PatchLang l);

// Compile `source` in `lang` for `ctx`. Never throws; failures land in diagnostics.
CompileResult CompilePatch(PatchLang lang, const std::string& source, const PatchCtx& ctx);

} // namespace ds
