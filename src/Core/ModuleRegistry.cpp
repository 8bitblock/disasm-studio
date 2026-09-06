#include "ModuleRegistry.h"

#include "AnalysisService.h"

#include <utility>

namespace ds {

ModuleAnalysisRoute ModuleRegistry::applyAnalysisResult(AnalysisResult&& result) {
    if (!result.moduleBase) return ModuleAnalysisRoute::Ignored;
    LoadedModule* module = byBase(result.moduleBase);
    if (!module || !module->analyzing || !module->analysisEpoch ||
        module->analysisEpoch != result.epoch)
        return ModuleAnalysisRoute::Ignored;

    if (result.failureValid) {
        module->analyzing = false;
        module->analysisComplete = false;
        module->analysisError = result.failure.empty()
                              ? "unknown module-analysis worker error"
                              : std::move(result.failure);
        constexpr size_t kMaxStoredFailure = 1024;
        if (module->analysisError.size() > kMaxStoredFailure)
            module->analysisError.resize(kMaxStoredFailure);
        return ModuleAnalysisRoute::Failed;
    }

    bool applied = false;
    if (result.stringsValid) {
        module->cache.strings = std::move(result.strings);
        module->cache.stringsTruncated = result.stringsTruncated;
        module->cache.stringsValid = true;
        applied = true;
    }
    if (result.funcsValid) {
        module->cache.functions = std::move(result.functions);
        module->cache.summary = std::move(result.summary);
        module->cache.codeData = std::move(result.codeData);
        module->cache.funcsValid = true;
        applied = true;
    }
    if (result.listingValid) {
        module->cache.listRows = std::move(result.listRows);
        module->cache.listingCodeBytes = result.listingCodeBytes;
        module->cache.listingCodePages = result.listingCodePages;
        module->cache.listingValid = true;
        applied = true;
    }
    if (result.xref) {
        module->cache.xref = std::move(result.xref);
        module->analyzing = false;
        module->analysisComplete = true;
        module->analysisError.clear();
        return ModuleAnalysisRoute::Completed;
    }
    return applied ? ModuleAnalysisRoute::Applied : ModuleAnalysisRoute::Ignored;
}

} // namespace ds
