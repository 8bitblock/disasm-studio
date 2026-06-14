#pragma once
//
// JvmAware.h
// Pure, header-only helpers that make the Win32 debugger JVM-aware (Java EXEs
// host a JVM via jvm.dll and intentionally raise access violations for null
// checks / safepoint polls, which would otherwise spam the debugger):
//   - recognize JVM runtime module names (jvm.dll / j9vm.dll / jli.dll),
//   - resolve an export's RVA by walking a remote module's export directory
//     through an abstract memory reader (no Windows headers needed), and
//   - classify an exception as "JVM-internal" (expected, pass through quietly).
//
// Like StepLogic.h this is decision logic only - no Win32 calls - so it is
// exercised off-target by tests/jvmaware_test.cpp with a fake memory reader.
//
#include <cctype>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>

namespace ds {

// Reads `n` bytes of debuggee memory at `va` into `out`; false on failure.
// The Debugger passes its readMemory; tests pass a lambda over a byte buffer.
using RemoteReader = std::function<bool(uint64_t va, void* out, size_t n)>;

namespace jvmdetail {
// Lowercased file name (path stripped) of a module name or full path.
inline std::string baseNameLower(const std::string& nameOrPath) {
    size_t s = nameOrPath.find_last_of("/\\");
    std::string b = (s == std::string::npos) ? nameOrPath : nameOrPath.substr(s + 1);
    for (char& c : b) c = (char)std::tolower((unsigned char)c);
    return b;
}
} // namespace jvmdetail

// Any module of a hosted Java runtime (drives the "JVM" badge): the VM itself
// (HotSpot jvm.dll, OpenJ9 j9vm.dll) or the launcher library jli.dll.
inline bool IsJvmModuleName(const std::string& nameOrPath) {
    const std::string b = jvmdetail::baseNameLower(nameOrPath);
    return b == "jvm.dll" || b == "j9vm.dll" || b == "jli.dll";
}

// The VM module proper - the one that exports JNI_CreateJavaVM and whose code
// range bounds "JVM-internal" exceptions. jli.dll deliberately doesn't count.
inline bool IsJvmVmModuleName(const std::string& nameOrPath) {
    const std::string b = jvmdetail::baseNameLower(nameOrPath);
    return b == "jvm.dll" || b == "j9vm.dll";
}

// Resolve `exportName` in the module mapped at `base` by walking its PE export
// directory through `read`. Returns the export's RVA, or 0 when the module has
// no such export / anything is malformed. Bounded + 64-bit wrap-proof in the
// same style as BinaryFile::parseImports (a hostile remote image must not be
// able to spin or overflow us). Forwarder RVAs are returned as-is (the caller
// plants a breakpoint; a forwarded JNI_CreateJavaVM doesn't occur in practice).
inline uint32_t FindExportRVA(const RemoteReader& read, uint64_t base, const char* exportName) {
    if (!read || !base || !exportName || !*exportName) return 0;
    auto rd32 = [&](uint64_t va, uint32_t& v) { v = 0; return read(va, &v, 4); };
    auto rd16 = [&](uint64_t va, uint16_t& v) { v = 0; return read(va, &v, 2); };

    uint16_t mz = 0;
    if (!rd16(base, mz) || mz != 0x5A4D) return 0;            // "MZ"
    uint32_t e_lfanew = 0;
    if (!rd32(base + 0x3C, e_lfanew) || !e_lfanew || e_lfanew > 0x10000000u) return 0;
    uint32_t sig = 0;
    if (!rd32(base + e_lfanew, sig) || sig != 0x00004550u) return 0;   // "PE\0\0"

    const uint64_t opt = base + e_lfanew + 4 + 20;
    uint16_t magic = 0;
    if (!rd16(opt, magic)) return 0;
    const uint64_t dataDir = opt + (magic == 0x20B ? 112 : magic == 0x10B ? 96 : 0);
    if (dataDir == opt) return 0;
    uint32_t numDirs = 0;
    if (!rd32(dataDir - 4, numDirs) || numDirs == 0) return 0;
    uint32_t expRVA = 0, expSize = 0;
    if (!rd32(dataDir, expRVA) || !rd32(dataDir + 4, expSize) || !expRVA) return 0;

    // IMAGE_EXPORT_DIRECTORY: +20 NumberOfFunctions, +24 NumberOfNames,
    // +28 AddressOfFunctions, +32 AddressOfNames, +36 AddressOfNameOrdinals.
    const uint64_t ed = base + expRVA;
    uint32_t nFuncs = 0, nNames = 0, funcsRVA = 0, namesRVA = 0, ordsRVA = 0;
    if (!rd32(ed + 20, nFuncs) || !rd32(ed + 24, nNames) ||
        !rd32(ed + 28, funcsRVA) || !rd32(ed + 32, namesRVA) || !rd32(ed + 36, ordsRVA))
        return 0;
    if (!nNames || !funcsRVA || !namesRVA || !ordsRVA) return 0;
    if (nNames > 0x20000u || nFuncs > 0x20000u) return 0;     // hostile counts

    const size_t want = std::strlen(exportName);
    if (want == 0 || want > 255) return 0;
    char buf[256];
    for (uint32_t i = 0; i < nNames; ++i) {
        uint32_t nameRVA = 0;
        if (!rd32(base + (uint64_t)namesRVA + 4ull * i, nameRVA) || !nameRVA) continue;
        if (!read(base + nameRVA, buf, want + 1)) continue;    // name + its terminator
        if (std::memcmp(buf, exportName, want) != 0 || buf[want] != '\0') continue;
        uint16_t ord = 0;
        if (!rd16(base + (uint64_t)ordsRVA + 2ull * i, ord) || ord >= nFuncs) return 0;
        uint32_t fnRVA = 0;
        if (!rd32(base + (uint64_t)funcsRVA + 4ull * ord, fnRVA)) return 0;
        return fnRVA;
    }
    return 0;
}

// True when an exception is JVM machinery rather than a bug: HotSpot/OpenJ9
// intentionally take access violations (implicit null checks, safepoint polls)
// and illegal-instruction traps inside the VM module. Scoped to the VM module's
// code range -- a fault in user/JIT code outside it still surfaces normally.
inline bool IsJvmInternalException(uint32_t code, uint64_t pc, uint64_t jvmBase, uint64_t jvmSize) {
    if (!jvmBase || !jvmSize) return false;
    if (code != 0xC0000005u /*ACCESS_VIOLATION*/ &&
        code != 0xC000001Du /*ILLEGAL_INSTRUCTION*/) return false;
    return pc >= jvmBase && pc - jvmBase < jvmSize;
}

} // namespace ds
