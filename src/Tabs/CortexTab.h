#pragma once
#include "ITab.h"
#include "../Core/Cortex.h"
#include "../Core/TechScan.h"     // Capability
#include "../Core/AlgoScan.h"     // AlgoMatch
#include "../Core/AnalysisJobs.h" // FuncResult, StrResult
#include "../Core/XrefIndex.h"

#include <string>
#include <utility>
#include <vector>

namespace ds {

// Cortex: the "reverse-engineering brain" (additions.md idea #3). Runs the existing
// analyzers over the loaded binary, then reasons over their output (Core/Cortex) to
// produce a plain-English verdict, merged behaviours, per-function briefs, and a
// deterministic "chat with the binary" Q&A box. No model dependency — the reasoning
// is grounded in the static evidence and honest about its confidence.
class CortexTab final : public ITab {
public:
    const char* name() const override { return "Cortex"; }
    void render(AppContext& ctx) override;

private:
    void analyze(AppContext& ctx);          // (re)run the pipeline + build the report
    void ask(AppContext& ctx, const std::string& q);
    CortexInput inputFor(AppContext& ctx);  // CortexInput over the cached vectors

    // Cached analysis inputs — kept alive because AskCortex holds pointers into them.
    std::vector<Capability>     caps_;
    std::vector<AlgoMatch>      algos_;
    std::vector<FuncResult>     funcs_;
    std::vector<StrResult>      strings_;
    std::vector<CortexFuncInfo> funcInfo_;   // per-function annotation facts (FuncAnnotate)
    XrefIndex                   xref_;
    CortexReport                rep_;

    bool     analyzed_     = false;
    uint64_t analyzedHash_ = 0;     // binary content hash the report was built for
    uint64_t analyzedRevision_ = 0; // patched/reloaded image generation
    uint64_t analyzedKnowledge_ = 0;// project renames/confirmed algorithm labels
    Engine   analyzedEngine_ = Engine::Zydis;
    Arch     analyzedArch_   = Arch::X64;
    int      behSel_       = -1;
    char     input_[512]   = "";
    std::vector<std::pair<std::string, std::string>> chat_;   // (question, answer)
    bool     scrollChat_   = false;
};

} // namespace ds
