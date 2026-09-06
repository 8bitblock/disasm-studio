#pragma once
//
// ModuleRegistry.h
// Holds every module of an attached process (the main EXE + all DLLs) so the whole
// program — not just one on-disk binary — is browsable/disassemblable. Each module
// owns its mapped image (read from the live process via BinaryFile::loadFromMemory)
// and a cache of its analysis results, so switching the active module is instant once
// analyzed and an "analyze all modules" batch can fan out across the worker pool
// (each job reads its own module's BinaryFile).
//
// Pure Core (no ImGui/Win32): the registry is just data + lookups, unit-testable in
// isolation (see tests/module_registry_test.cpp). Liveness (LOAD_DLL/UNLOAD_DLL) and
// reading module images from the debuggee are wired by the UI/Debugger layer.
//
#include "BinaryFile.h"
#include "AnalysisJobs.h"   // StrResult, FuncResult, ListRowR
#include "XrefIndex.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ds {

struct AnalysisResult;

// Result of routing one app-global module-analysis completion.  The caller uses
// Failed to surface the structured worker error; Ignored covers stale epochs and
// results for modules which were unloaded before publication.
enum class ModuleAnalysisRoute : uint8_t {
    Ignored = 0,
    Applied,
    Completed,
    Failed,
};

// Per-module analysis results for the registry's captured image. A newly captured
// static-document image is analyzed independently: this cache has neither exact
// capture identity nor a complete decoder configuration to authorize replay.
struct ModuleAnalysisCache {
    std::vector<FuncResult>    functions;
    std::vector<StrResult>     strings;
    std::vector<ListRowR>      listRows;
    std::shared_ptr<const CodeDataMap> codeData;
    uint64_t                   listingCodeBytes = 0;
    uint64_t                   listingCodePages = 0;
    std::shared_ptr<XrefIndex> xref;
    std::string                summary;
    bool stringsTruncated = false;
    bool funcsValid = false, stringsValid = false, listingValid = false;
    void clear() { functions.clear(); strings.clear(); listRows.clear();
                   listingCodeBytes = listingCodePages = 0;
                   codeData.reset(); xref.reset(); summary.clear(); stringsTruncated = false;
                   funcsValid = stringsValid = listingValid = false; }
};

struct LoadedModule {
    std::string name;                 // "ntdll.dll", main exe file name
    std::string path;                 // on-disk path if known (may be empty)
    uint64_t    base = 0;             // runtime base in the debuggee
    uint64_t    size = 0;             // image size
    MachineArch arch = MachineArch::Unknown;
    bool        isMain = false;       // the process's main executable
    bool        imageLoaded = false;  // bin holds this module's mapped image
    bool        analyzing = false;    // image read or background analysis is in flight/queued
    bool        analysisComplete = false; // every requested analysis pass was adopted
    uint64_t    analysisEpoch = 0;    // rejects results from a cancelled/base-reused job
    std::string analysisError;        // structured worker/drop failure, empty on success
    BinaryFile  bin;                  // mapped image (empty until imageLoaded)
    ModuleAnalysisCache cache;        // analysis results (valid once analyzed)

    bool analyzed() const { return analysisComplete; }
    bool contains(uint64_t va) const { return base && va >= base && va - base < size; }
};

class ModuleRegistry {
public:
    void   clear() { mods_.clear(); active_ = -1; }
    bool   empty() const { return mods_.empty(); }
    size_t size()  const { return mods_.size(); }
    const std::vector<std::unique_ptr<LoadedModule>>& all() const { return mods_; }

    LoadedModule* at(int i) { return (i >= 0 && i < (int)mods_.size()) ? mods_[i].get() : nullptr; }

    // Insert (or update) a module keyed by runtime base. Returns the entry.
    LoadedModule* addOrUpdate(const std::string& name, uint64_t base, uint64_t size,
                              const std::string& path = "") {
        if (LoadedModule* m = byBase(base)) {
            if (!name.empty()) m->name = name;
            if (size) m->size = size;
            if (!path.empty()) m->path = path;
            return m;
        }
        auto m = std::make_unique<LoadedModule>();
        m->name = name; m->base = base; m->size = size; m->path = path;
        mods_.push_back(std::move(m));
        return mods_.back().get();
    }

    LoadedModule* byBase(uint64_t base) {
        for (auto& m : mods_) if (m->base == base) return m.get();
        return nullptr;
    }
    int indexByBase(uint64_t base) const {
        for (int i = 0; i < (int)mods_.size(); ++i) if (mods_[i]->base == base) return i;
        return -1;
    }
    // The module whose [base, base+size) contains `va`, or nullptr.
    LoadedModule* containing(uint64_t va) {
        for (auto& m : mods_) if (m->contains(va)) return m.get();
        return nullptr;
    }

    void removeByBase(uint64_t base) {
        int idx = indexByBase(base);
        if (idx < 0) return;
        mods_.erase(mods_.begin() + idx);
        if (active_ == idx) active_ = -1;
        else if (active_ > idx) --active_;
    }

    int           activeIndex() const { return active_; }
    LoadedModule* active() { return at(active_); }
    void          setActive(int i) { active_ = (i >= 0 && i < (int)mods_.size()) ? i : -1; }
    void          setActiveByBase(uint64_t base) { active_ = indexByBase(base); }

    // Adopt one immutable result from the app-global module AnalysisService.
    // Module analysis requests always include K_Xref, whose result is the final
    // pass for this bounded cache.  Epoch + base matching makes unload/base reuse
    // fail closed instead of writing into a replacement module.
    ModuleAnalysisRoute applyAnalysisResult(AnalysisResult&& result);

private:
    std::vector<std::unique_ptr<LoadedModule>> mods_;
    int active_ = -1;
};

} // namespace ds
