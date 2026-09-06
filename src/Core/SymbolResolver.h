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

// DbgHelp does not have a per-session "offline" switch: passing a null search
// path lets environment variables opt the process into a symbol server.  Keep an
// explicit, local-only search path unless the analyst deliberately enables the
// network tier.
struct SymbolResolverOptions {
    bool        networkEnabled = false;
    std::string cacheDirectory;
    std::string serverUrl = "https://msdl.microsoft.com/download/symbols";
    bool        collectSourceLines = true;
    bool        collectTypes = true;
    bool        collectLocals = true;
};

struct SymbolSourceLine {
    std::string file;
    uint32_t    line = 0;
    uint32_t    displacement = 0;
};

struct SymbolLocal {
    std::string name;
    std::string type;
    std::string location;
    bool        parameter = false;
};

struct SymbolRecord {
    bool                    found = false;
    uint64_t                queryAddress = 0;
    uint64_t                symbolAddress = 0;
    uint64_t                displacement = 0;
    std::string             name;
    SymbolSourceLine        source;
    std::string             prototype;
    std::vector<SymbolLocal> locals;
};

// Pure policy helper used by tests and diagnostics. Offline options never emit
// an SRV component, so _NT_SYMBOL_PATH cannot silently opt the app into network.
std::string BuildSymbolSearchPath(const SymbolResolverOptions& options,
                                  const std::string& binaryPath = {});

class SymbolResolver {
public:
    ~SymbolResolver();

    // Must be set before binding a session. Changing it resets the current
    // session so DbgHelp never carries a previous network search path forward.
    void configure(SymbolResolverOptions options);

    // Bind to the live debuggee via its process handle (re-binds if it changed).
    bool useLive(void* hProcess);
    // Bind to a loaded binary file (static / not-attached) at the given image base.
    bool useBinary(const std::string& path, uint64_t imageBase);
    void reset();

    // Live mode: register the module covering an address so its symbols can load.
    void ensureModule(uint64_t base, uint64_t size, const std::string& imagePath);

    // Resolve addr -> undecorated symbol name (+ displacement). false if none.
    bool resolve(uint64_t addr, std::string& nameOut, uint64_t& dispOut);

    // Rich form used by the asynchronous SymbolService. Source/type/local
    // discovery is bounded and best-effort; `found` still means the symbol name
    // itself resolved even when optional PDB records were unavailable.
    bool resolveDetailed(uint64_t addr, SymbolRecord& recordOut);

    // Reverse lookup: resolve a symbol name -> address via DbgHelp (PDB/exports).
    // false if not found. Used by the "go to name" box as an extra source.
    bool addressOf(const std::string& name, uint64_t& addrOut);

private:
    void*                 h_ = nullptr;
    bool                  inited_ = false;
    bool                  live_ = false;
    std::string           binaryPath_;
    uint64_t              binaryImageBase_ = 0;
    std::vector<uint64_t> loaded_;   // module bases registered in live mode
    SymbolResolverOptions options_;
};

} // namespace ds
