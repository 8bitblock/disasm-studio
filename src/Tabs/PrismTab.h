#pragma once
#include "ITab.h"
#include "../Core/Prism.h"
#include "../Core/PrismSampler.h"

#include <memory>

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
    void renderReportPanes(AppContext& ctx, const PrismReport& report,
                           const DbgSnapshot& navigationSnapshot,
                           uint64_t sampledCreationTime, bool canNavigate);

    PrismSampler sampler_;
    char         pidBuf_[16] = "";
    std::string  shownError_;
    int          startMode_ = 0;
    int          selectedTimeline_ = -1;
    int          selectedFlame_ = -1;
    bool         stopRequested_ = false;
    int          compactReportView_ = 0;

    // Retained ratios for the draggable functions | details | paths panes.
    // Boundaries are expressed against the available content width so the
    // layout remains stable across window and DPI changes.
    float        firstPaneSplit_ = 0.40f;
    float        secondPaneSplit_ = 0.70f;
};

} // namespace ds
