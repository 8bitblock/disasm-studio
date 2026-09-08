#include "Core/DebuggerMemoryMutation.h"
#include "Core/DebuggerInternal.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <set>

using namespace ds::debugger_detail;
struct FakeMemory {
    std::vector<uint8_t> bytes{0x90, 0x91};
    uint32_t protections[2]{2, 4};
    int reads = 0, writes = 0, protects = 0, flushes = 0;
    std::set<int> badReads, badWrites, partialWrites, badProtects, badFlushes;
    bool read(uint64_t, void* out, size_t size) {
        if (badReads.contains(++reads)) return false;
        std::memcpy(out, bytes.data(), size); return true;
    }
    bool write(uint64_t, const void* in, size_t size) {
        ++writes;
        if (badWrites.contains(writes)) return false;
        if (partialWrites.contains(writes)) {
            bytes[0] = *static_cast<const uint8_t*>(in); return false;
        }
        std::memcpy(bytes.data(), in, size); return true;
    }
    bool protect(uint64_t address, size_t, uint32_t protection) {
        if (badProtects.contains(++protects)) return false;
        protections[address - 0x1000] = protection; return true;
    }
    bool protectionMatches(uint64_t address, size_t, uint32_t protection) {
        return protections[address - 0x1000] == protection;
    }
    bool flush(uint64_t, size_t) { return !badFlushes.contains(++flushes); }
};
MemoryMutation plan() {
    MemoryMutation state;
    state.address = 0x1000;
    state.original = {0x90, 0x91}; state.replacement = {0xCC, 0xCC};
    state.working.resize(2); state.verified.resize(2);
    state.regions = {{0x1000, 1, 2, 0x40}, {0x1001, 1, 4, 0x40}};
    return state;
}
int main() {
    {
        FakeMemory io; auto state = plan();
        assert(ApplyMemoryMutation(io, state));
        assert(!MemoryMutationPending(state) && !state.failures);
        assert(io.bytes == state.replacement && io.protections[0] == 2 && io.protections[1] == 4);
    }
    {
        FakeMemory io; auto state = plan(); io.badProtects = {2};
        assert(!ApplyMemoryMutation(io, state) && io.writes == 0);
        assert(!MemoryMutationPending(state) && (state.failures & MutationProtectFailed));
        assert(io.protections[0] == 2 && io.protections[1] == 4);
    }
    {
        FakeMemory io; auto state = plan(); io.partialWrites = {1};
        assert(!ApplyMemoryMutation(io, state));
        assert(io.bytes == state.original && !MemoryMutationPending(state));
        assert((state.failures & MutationWriteFailed) && io.flushes == 1);
    }
    {
        FakeMemory io; auto state = plan(); io.badReads = {1, 2};
        assert(!ApplyMemoryMutation(io, state) && MemoryMutationPending(state));
        assert(io.bytes == state.replacement && state.rollbackPending);
        assert(ReconcileMemoryMutation(io, state) && io.bytes == state.original);
    }
    {
        FakeMemory io; auto state = plan(); io.partialWrites = {1}; io.badWrites = {2};
        assert(!ApplyMemoryMutation(io, state) && MemoryMutationPending(state));
        assert(io.bytes[0] == 0xCC); // failed install still retains byte ownership
        io.bytes[1] = 0x77;         // superseding changes must survive retry
        assert(ReconcileMemoryMutation(io, state));
        assert(io.bytes == std::vector<uint8_t>({0x90, 0x77}));
    }
    {
        FakeMemory io; auto state = plan(); io.badProtects = {3};
        assert(ApplyMemoryMutation(io, state) && MemoryMutationPending(state));
        assert(io.bytes == state.replacement); // successful INT3 keeps its ordinary owner
        assert(state.failures & MutationRestoreProtectionFailed);
        assert(ReconcileMemoryMutation(io, state) && io.bytes == state.replacement);
        assert(io.protections[0] == 2 && io.protections[1] == 4);
    }
    {
        FakeMemory io; auto state = plan(); io.badFlushes = {1, 2};
        assert(ApplyMemoryMutation(io, state) && MemoryMutationPending(state));
        assert(!ReconcileMemoryMutation(io, state) && MemoryMutationPending(state));
        assert(ReconcileMemoryMutation(io, state) && io.bytes == state.replacement);
        assert(state.failures & MutationFlushFailed);
    }
    // Native adapter checks exact protections across a page boundary and leaves
    // no executable permissions on data, no lingering handle/ledger ownership.
    SYSTEM_INFO info{}; GetSystemInfo(&info);
    const size_t page = info.dwPageSize;
    auto* memory = static_cast<uint8_t*>(VirtualAlloc(nullptr, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    assert(memory);
    memory[page - 1] = 0x90; memory[page] = 0x91;
    DWORD old = 0;
    assert(VirtualProtect(memory, page, PAGE_READONLY, &old));
    assert(VirtualProtect(memory + page, page, PAGE_EXECUTE_READ, &old));
    const uint8_t change[]{0xCC, 0xCC};
    const auto address = reinterpret_cast<uint64_t>(memory + page - 1);
    assert(ds::writeRemoteExact(GetCurrentProcess(), address, change, 2));
    assert(memory[page - 1] == 0xCC && memory[page] == 0xCC);
    MEMORY_BASIC_INFORMATION first{}, second{};
    assert(VirtualQuery(memory, &first, sizeof(first)) && first.Protect == PAGE_READONLY);
    assert(VirtualQuery(memory + page, &second, sizeof(second)) && second.Protect == PAGE_EXECUTE_READ);
    assert(ds::restoreDebuggerOwnedByte(GetCurrentProcess(), address, 0x90));
    assert(memory[page - 1] == 0x90 && !ds::nativeMutationsPending());
    std::string error;
    assert(ds::reconcileNativeMutations(error) && error.empty());
    assert(ds::consumeNativeMutationFailure().empty());
    assert(VirtualFree(memory, 0, MEM_RELEASE));
    std::cout << "debugger_memory_mutation_test: all checks passed\n";
}
