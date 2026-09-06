#pragma once
#include "ITab.h"
#include "../Core/DocumentResultIdentity.h"
#include "../Core/Cortex.h"
#include "../Core/TechScan.h"     // Capability
#include "../Core/AlgoScan.h"     // AlgoMatch
#include "../Core/AnalysisJobs.h" // FuncResult, StrResult
#include "../Core/CrackmeTriage.h"
#include "../Core/XrefIndex.h"

#include <string>
#include <memory>
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
    CortexTab();
    ~CortexTab() override;

    const char* name() const override { return "Cortex"; }
    void render(AppContext& ctx) override;

private:
    void analyze(AppContext& ctx);          // queue the pipeline on the owned worker
    void pumpAnalysis(AppContext& ctx);     // bounded snapshot staging + result adoption
    void cancelAnalysis();
    void ask(AppContext& ctx, const std::string& q);
    CortexInput inputFor(AppContext& ctx);  // CortexInput over the cached vectors

    // Kept behind a pimpl so thread/mutex details stay out of this UI-facing
    // header. The tab owns and joins the worker; it never borrows BinaryFile or
    // the UI decoder after analyze() returns.
    struct AsyncState;
    std::unique_ptr<AsyncState> async_;

    // Cached analysis inputs — kept alive because AskCortex holds pointers into them.
    std::vector<Capability>     caps_;
    std::vector<AlgoMatch>      algos_;
    std::vector<FuncResult>     funcs_;
    std::vector<StrResult>      strings_;
    std::vector<CortexFuncInfo> funcInfo_;   // per-function annotation facts (FuncAnnotate)
    XrefIndex                   xref_;
    CrackmeTriageReport         crackmeTriage_;
    CortexReport                rep_;

    bool     analyzed_     = false;
    DocumentResultIdentity observedIdentity_;
    DocumentResultIdentity analyzedIdentity_;
    uint64_t analyzedKnowledge_ = 0;// project renames/confirmed algorithm labels
    Engine   analyzedEngine_ = Engine::Zydis;
    Arch     analyzedArch_   = Arch::X64;
    int      behSel_       = -1;
    char     input_[512]   = "";
    std::vector<std::pair<std::string, std::string>> chat_;   // (question, answer)
    bool     scrollChat_   = false;

    // Retained IDE-pane splits. Ratios survive resizes/DPI changes without
    // turning the report back into a rigid 50/50 dashboard on every frame.
    float    behaviorPaneRatio_ = 0.50f;
    float    chatPaneRatio_     = 0.30f;
};

} // namespace ds
