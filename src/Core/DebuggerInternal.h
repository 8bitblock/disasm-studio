#pragma once
// Private native adapters shared by the breakpoint, observer, and event owner
// implementations. Mutating calls require a stopped debug event on its owner.
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <string>
namespace ds {
bool readByteRPM(HANDLE h, uint64_t va, uint8_t& b);
bool writeByteRPM(HANDLE h, uint64_t va, uint8_t b);
bool replaceByteIfEqual(HANDLE h, uint64_t va, uint8_t expected, uint8_t replacement);
bool restoreDebuggerOwnedByte(HANDLE h, uint64_t va, uint8_t original);
bool readRemoteExact(HANDLE h, uint64_t va, void* out, size_t size);
bool writeRemoteExact(HANDLE h, uint64_t va, const void* in, size_t size);
// Thread-local to the sole debug-event owner. A verified byte write can return
// true while protection/cache restoration remains pending, preserving its
// ordinary breakpoint owner. Failed/uncertain writes retain rollback ownership
// here. Reconcile before releasing any stopped event or live process handle.
bool nativeMutationsPending();
bool reconcileNativeMutations(std::string& error);
std::string consumeNativeMutationFailure();
std::wstring widenUtf8(const std::string& s);
}
