#pragma once
#include "ITab.h"
#include "../Core/Prism.h"
#include "../Core/PrismSampler.h"

namespace ds {

// Prism: the explanatory profiler (additions.md idea #5). Samples a running process,
// then — instead of a raw flame graph — tells you in plain English WHERE the time goes
// and WHY (CPU-bound vs blocked waiting vs lock contention vs allocation vs I/O), with a
// hot-function table, a thread-state breakdown, and the hottest call paths.
class PrismTab final : public ITab {
public:
    const char* name() const override { return "Prism"; }
    void render(AppContext& ctx) override;

private:
    void rebuild();   // aggregate the sampler's snapshot into rep_

    PrismSampler sampler_;
    PrismReport  rep_;
    char         pidBuf_[16] = "";
    double       lastBuild_  = 0.0;   // ImGui::GetTime() of the last rebuild (throttle)
    bool         autoRefresh_ = true;
    std::string  shownError_;
    uint64_t     builtGeneration_ = 0;
};

} // namespace ds
