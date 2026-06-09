#pragma once
#include "ITab.h"
#include "../Core/TechScan.h"
#include <string>
#include <vector>

namespace ds {

// Binary Tech: run a "tech scan" that detects real capabilities/techniques in
// the loaded binary (imports, packer sections, byte patterns); select a
// capability to inspect the associated code and jump to it in the Binary View.
class BinaryTechTab final : public ITab {
public:
    const char* name() const override { return "Binary Tech"; }
    void render(AppContext& ctx) override;

private:
    void runTechScan(AppContext& ctx);

    std::vector<Capability> caps_;     // from ScanCapabilities (Core/TechScan)
    int   selected_ = -1;
    bool  scanned_  = false;
    char  filter_[64] = "";
};

} // namespace ds
