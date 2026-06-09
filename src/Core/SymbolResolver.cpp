#include "SymbolResolver.h"
#include "DbgHelpLock.h"   // serialize all DbgHelp use against the debug thread's StackWalk64

#include <windows.h>
#include <dbghelp.h>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")

namespace ds {

SymbolResolver::~SymbolResolver() { reset(); }

void SymbolResolver::reset() {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (inited_ && h_) SymCleanup((HANDLE)h_);
    inited_ = false; h_ = nullptr; live_ = false;
    loaded_.clear(); binaryPath_.clear();
}

void SymbolResolver::useLive(void* hProcess) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (inited_ && live_ && h_ == hProcess) return;   // already bound to this process
    reset();
    if (!hProcess) return;
    // DEFERRED_LOADS: don't load a module's PDB until first queried. No prompts /
    // critical-error popups. No symbol server set -> only local PDBs + exports
    // (avoids network, which is unreliable here).
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
    if (SymInitialize((HANDLE)hProcess, nullptr, FALSE)) { inited_ = true; live_ = true; h_ = hProcess; }
}

void SymbolResolver::useBinary(const std::string& path, uint64_t imageBase) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (inited_ && !live_ && binaryPath_ == path) return;
    reset();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
    HANDLE fake = (HANDLE)(ULONG_PTR)0x1;   // a distinct "process" id for the file session
    if (SymInitialize(fake, nullptr, FALSE)) {
        inited_ = true; live_ = false; h_ = (void*)fake; binaryPath_ = path;
        SymLoadModuleEx(fake, nullptr, path.c_str(), nullptr, imageBase, 0, nullptr, 0);  // size 0 -> from PE headers
    }
}

void SymbolResolver::ensureModule(uint64_t base, uint64_t size, const std::string& imagePath) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (!inited_ || !live_ || !base) return;
    if (std::find(loaded_.begin(), loaded_.end(), base) != loaded_.end()) return;
    loaded_.push_back(base);
    SymLoadModuleEx((HANDLE)h_, nullptr, imagePath.empty() ? nullptr : imagePath.c_str(), nullptr,
                    base, (DWORD)size, nullptr, 0);
}

bool SymbolResolver::resolve(uint64_t addr, std::string& nameOut, uint64_t& dispOut) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (!inited_ || !h_) return false;
    // SYMBOL_INFO + room for the name; ULONG64 array guarantees 8-byte alignment.
    ULONG64 buffer[(sizeof(SYMBOL_INFO) + 512 + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
    SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(buffer);
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen   = 511;
    DWORD64 disp = 0;
    if (SymFromAddr((HANDLE)h_, addr, &disp, si) && si->NameLen) {
        nameOut.assign(si->Name, si->NameLen);
        dispOut = (uint64_t)disp;
        return true;
    }
    return false;
}

bool SymbolResolver::addressOf(const std::string& name, uint64_t& addrOut) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (!inited_ || !h_ || name.empty()) return false;
    ULONG64 buffer[(sizeof(SYMBOL_INFO) + 512 + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
    SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(buffer);
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen   = 511;
    if (SymFromName((HANDLE)h_, name.c_str(), si) && si->Address) {
        addrOut = (uint64_t)si->Address;
        return true;
    }
    return false;
}

} // namespace ds
