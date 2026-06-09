#pragma once
//
// SymbolResolver.h
// Thin DbgHelp wrapper that resolves addresses to symbol names: rich PDB names
// when a .pdb is available (the target if it ships one, or cached system PDBs),
// and export-table names otherwise. Degrades gracefully (resolve() returns false)
// so callers fall back to their own export/heuristic naming.
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

class SymbolResolver {
public:
    ~SymbolResolver();

    // Bind to the live debuggee via its process handle (re-binds if it changed).
    void useLive(void* hProcess);
    // Bind to a loaded binary file (static / not-attached) at the given image base.
    void useBinary(const std::string& path, uint64_t imageBase);
    void reset();

    // Live mode: register the module covering an address so its symbols can load.
    void ensureModule(uint64_t base, uint64_t size, const std::string& imagePath);

    // Resolve addr -> undecorated symbol name (+ displacement). false if none.
    bool resolve(uint64_t addr, std::string& nameOut, uint64_t& dispOut);

    // Reverse lookup: resolve a symbol name -> address via DbgHelp (PDB/exports).
    // false if not found. Used by the "go to name" box as an extra source.
    bool addressOf(const std::string& name, uint64_t& addrOut);

private:
    void*                 h_ = nullptr;
    bool                  inited_ = false;
    bool                  live_ = false;
    std::string           binaryPath_;
    std::vector<uint64_t> loaded_;   // module bases registered in live mode
};

} // namespace ds
