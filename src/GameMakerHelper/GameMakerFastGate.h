#pragma once
#include <cstddef>
#include <cstdint>

// Private MASM/C++ cache. Colliding thread ids always use the complete gate.
// Only the owning thread writes a claimed row. Native interpreter entry clears
// its context field, so reused native frames never inherit an old invocation.
struct alignas(64) DsGmlFastThread {
    uint32_t tid = 0;
    uint32_t depth = 0;
    uint64_t context = 0;
    uint64_t code = 0;
    uint64_t anchor = 0;
    uint32_t countdown = 0;
    uint32_t reserved = 0;
    uint32_t rootCodeIndex = 0;
    uint32_t activeCodeIndex = 0;
    uint64_t padding[2]{};
};
static_assert(sizeof(DsGmlFastThread) == 64 && offsetof(DsGmlFastThread, rootCodeIndex) == 40);
inline constexpr uint32_t kDsGmlFastThreads = 64;
inline constexpr uint32_t kDsGmlBreakpointBloomBytes = 65536;
inline constexpr uint32_t kDsGmlBreakpointBloomMask = kDsGmlBreakpointBloomBytes * 8 - 1;
constexpr uint32_t DsGmlBreakpointBloomBit(uint32_t codeIndex, uint32_t byteOffset) {
    return ((codeIndex * 0x9e3779b1u) ^ (byteOffset >> 2)) & kDsGmlBreakpointBloomMask;
}
