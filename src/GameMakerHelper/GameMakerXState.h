#pragma once
#include <cstdint>
#include <intrin.h>

// Standard XSAVE area, Intel SDM vol. 1 section 13.4. Bound admission at
// initialization so insertion gates never query CPUID or allocate storage.
struct DsGmlXStateLayout { uint64_t mask=0; uint32_t bytes=512; };
inline bool DsGmlReadXStateLayout(DsGmlXStateLayout& out) noexcept {
    out={};
    int cpu[4]{};__cpuid(cpu,1);
    if((uint32_t(cpu[2])&((1u<<26)|(1u<<27)))!=((1u<<26)|(1u<<27)))return true;
    const uint64_t enabled=_xgetbv(0);
    __cpuidex(cpu,13,0);
    const uint64_t supported=uint32_t(cpu[0])|(uint64_t(uint32_t(cpu[3]))<<32);
    const uint32_t bytes=uint32_t(cpu[1]);
    if((enabled&3)!=3 || (enabled&~supported) || bytes<576 || bytes>16384)return false;
    out.mask=enabled;out.bytes=bytes;return true;
}
