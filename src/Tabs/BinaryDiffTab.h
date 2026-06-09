#pragma once
#include "ITab.h"
#include "../Core/BinaryFile.h"
#include "../Disasm/IDisassembler.h"
#include <memory>
#include <string>
#include <vector>

namespace ds {

// Binary diff: load two binaries and review byte/section differences.
class BinaryDiffTab final : public ITab {
public:
    const char* name() const override { return "Binary Diff"; }
    void render(AppContext& ctx) override;

private:
    void openInto(BinaryFile& target);
    void computeDiff();
    void computeSectionDiff();   // section-aware: align matching section names, then diff
    void buildRegions();         // coalesce differing offsets into navigable regions
    void gotoRegion(int idx);    // select region idx and scroll both panes to it
    void ensureDecoders();       // (re)build a per-binary decoder when its arch changes
    void renderDiffAsm();        // side-by-side disassembly of the selected region
    void renderLoadZone();
    void renderPane(const char* id, const BinaryFile& self, const BinaryFile& other,
                    int rows, bool master, float& scrollOut, bool& hoveredOut, bool forceScroll);

    struct DiffRow { uint64_t offset; uint8_t a; uint8_t b; };

    // A run of differing file offsets, coalesced across small gaps so one changed
    // instruction is a single navigable unit. Used by Prev/Next and the ASM panel.
    struct DiffRegion { uint64_t start = 0, end = 0; };

    // One aligned section pair (section-aware mode). `lOff`/`rOff` are the raw
    // file offsets of the section in each binary; `len` is the overlap compared.
    struct SecDiff {
        std::string name;
        uint64_t    lOff = 0, rOff = 0;   // raw file offset of the section in each file
        uint64_t    rva  = 0;             // section RVA (shared key when names collide)
        size_t      len  = 0;             // bytes compared (min of the two raw sizes)
        size_t      diffBytes = 0;        // differing bytes within `len`
        bool        matched = false;      // a same-named/RVA section existed on both sides
    };

    BinaryFile           left_;
    BinaryFile           right_;
    std::vector<DiffRow> diffs_;
    bool                 computed_ = false;
    size_t               totalDiff_ = 0;
    char                 jump_[32] = "";

    // Section-aware alignment: when on, diffs are computed per matching section
    // (by name, falling back to RVA) instead of by flat file offset, so an
    // inserted/removed byte early in the file doesn't cascade every later
    // section into a false "all-different".
    bool                    sectionAware_ = false;
    std::vector<SecDiff>    secDiffs_;
    size_t                  secTotalDiff_ = 0;
    size_t                  secUnmatched_ = 0;   // sections present on only one side

    // Synchronized side-by-side scrolling: the hovered pane drives the shared
    // scroll position; the other pane follows.
    float                scrollY_    = 0.0f;
    bool                 leftMaster_ = true;

    // Navigable difference regions + the currently selected one. `applyScroll_`
    // forces both panes to the selected region for one frame (overriding the
    // hover-driven sync).
    std::vector<DiffRegion> regions_;
    int                     curRegion_   = -1;
    bool                    applyScroll_ = false;

    // Lazily-built per-binary decoders for the ASM panel, rebuilt when a file's
    // architecture changes (the two binaries may differ in arch).
    std::unique_ptr<IDisassembler> leftDis_, rightDis_;
    MachineArch                    leftDisArch_  = MachineArch::Unknown;
    MachineArch                    rightDisArch_ = MachineArch::Unknown;
};

} // namespace ds
