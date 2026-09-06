#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace ds {
// Internal, dependency-free boundary for fault testing the exact production
// code-write sequence. The caller owns the held debug event and module identity.
struct GmlHookMutationIo {
    void* owner=nullptr;
    bool (*read)(void*,uint64_t,void*,size_t)=nullptr;
    bool (*writeVerified)(void*,uint64_t,const void*,size_t)=nullptr;
    bool (*protect)(void*,uint64_t,size_t,uint32_t,uint32_t*)=nullptr;
    bool (*flush)(void*,uint64_t,size_t)=nullptr;
};
struct GmlHookMutationResult {
    bool success=false;
    bool mutationAttempted=false;
    bool originalProtectionKnown=false;
    uint32_t originalProtection=0;
};
inline GmlHookMutationResult MutateGmlHookBytes(const GmlHookMutationIo& io,uint64_t address,
    std::span<const uint8_t> expected,std::span<const uint8_t> replacement,uint32_t writableProtection) {
    GmlHookMutationResult result;
    if(!io.read || !io.writeVerified || !io.protect || !io.flush || !address || expected.empty() ||
       expected.size()!=replacement.size() || expected.size()>16 || expected.size()-1>UINT64_MAX-address)return result;
    std::array<uint8_t,16> before{};
    if(!io.read(io.owner,address,before.data(),expected.size()) || std::memcmp(before.data(),expected.data(),expected.size()))return result;
    if(!io.protect(io.owner,address,expected.size(),writableProtection,&result.originalProtection))return result;
    result.originalProtectionKnown=true;
    // Ownership must survive false returns after a partial/full write, rollback,
    // protection restoration, or instruction-cache failure. Cleanup rechecks
    // actual owned bytes; success=false never authorizes releasing a helper.
    result.mutationAttempted=true;
    bool ok=io.writeVerified(io.owner,address,replacement.data(),replacement.size());
    if(!ok)(void)io.writeVerified(io.owner,address,expected.data(),expected.size());
    uint32_t ignored=0;
    ok=io.protect(io.owner,address,expected.size(),result.originalProtection,&ignored) && ok;
    result.success=io.flush(io.owner,address,expected.size()) && ok;
    return result;
}
} // namespace ds
