#pragma once
#include "ITab.h"
#include "../Core/Project.h"
#include <string>
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
    bool     loaded_              = false;
    bool     selectedHashValid_   = false;
    bool     lastSeenBinaryLoaded_ = false;
    uint64_t selectedHash_        = 0;
    float    listWidth_           = 0.0f; // retained master/detail splitter width
    uint64_t lastSeenHash_        = ~0ull; // re-read the index when the active project changes
    char     filter_[256]         = {};
    std::string openError_;
};

} // namespace ds
