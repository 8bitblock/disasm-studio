#pragma once
//
// Demangle.h
// Bounded, dependency-light C/C++ symbol presentation shared by the loader,
// analyzer, debugger, exports/imports views, and source export. Raw spellings
// remain authoritative in BinaryFile; this layer is display-only so reverse
// lookup, PE forwarding, and runtime invocation never lose the linker name.
//

#include <cstddef>
#include <string>
#include <string_view>

namespace ds {

enum class DemangleScheme {
    None,
    Microsoft,
    Itanium,
    CDecoration,
};

struct DemangleResult {
    std::string    text;
    std::string    label;    // compact qualified identifier (no function prototype)
    DemangleScheme scheme = DemangleScheme::None;
    bool           complete = false; // the complete recognized encoding was consumed

    bool changed(std::string_view raw) const { return text != raw; }
};

// Parse one linker spelling. Work, recursion, input, and output are bounded so
// hostile symbol tables cannot turn loading or painting into unbounded work.
DemangleResult DemangleSymbol(std::string_view raw);

// Cached display form used by hot UI/analysis paths. The cache is thread-safe
// (background analysis and the render thread both use it) and capped.
std::string DemangleForDisplay(std::string_view raw);

// Compact form for assembly labels, decompiler name maps, xrefs, and source
// export. It preserves namespaces/templates but omits a duplicated prototype.
std::string DemangleForLabel(std::string_view raw);

// Test/diagnostic visibility; ordinary callers should not need these.
size_t DemangleCacheSize();
void   ClearDemangleCache();

} // namespace ds
