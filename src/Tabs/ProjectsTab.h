#pragma once
#include "ITab.h"
#include "../Core/Project.h"
#include <vector>

namespace ds {

// Projects tab: backed by the on-disk recents index (LoadRecents). Lists real
// recent targets, opens them, and shows the live project's analysis summary.
class ProjectsTab final : public ITab {
public:
    const char* name() const override { return "Projects"; }
    void render(AppContext& ctx) override;

private:
    void refresh();

    std::vector<RecentEntry> recents_;
    bool     loaded_       = false;
    int      selected_     = -1;
    uint64_t lastSeenHash_ = ~0ull;   // re-read the index when the active project changes
    std::string openError_;
};

} // namespace ds
