#pragma once
//
// DbgHelpLock.h
// DbgHelp's Sym*/StackWalk64 APIs are documented as process-global single-threaded:
// concurrent calls from more than one thread can crash or corrupt the symbol session.
// In DisasmStudio two threads use DbgHelp for the same debuggee — the SymbolService
// worker's duplicated-handle SymbolResolver session and the debug thread's independent
// local-only unwind session (StackWalk64 + SymFunctionTableAccess64/SymGetModuleBase64/
// SymFromAddr). Every DbgHelp access on either thread MUST be serialized through this one
// lock. It is recursive so a SymbolResolver method that calls another (e.g. useLive ->
// reset) does not self-deadlock.
//
#include <mutex>

namespace ds {

inline std::recursive_mutex& DbgHelpMutex() {
    static std::recursive_mutex m;
    return m;
}

} // namespace ds
