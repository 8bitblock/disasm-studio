#pragma once
#include "../App.h"

namespace ds {

// Every workbench tab implements this. The App owns the tabs and calls
// render(ctx) for each one inside the dockspace each frame.
class ITab {
public:
    virtual ~ITab() = default;
    virtual const char* name() const = 0;
    virtual void        render(AppContext& ctx) = 0;
};

} // namespace ds
