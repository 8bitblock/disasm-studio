#pragma once
#include "ITab.h"
#include "../Core/BinaryFile.h"
#include "../Core/DocumentResultIdentity.h"
#include "../Core/SemanticDiff.h"
#include "../Disasm/IDisassembler.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace ds {

// Binary diff: load two binaries and review byte/section differences.
class BinaryDiffTab final : public ITab {
public:
    BinaryDiffTab();
    ~BinaryDiffTab() override;

    const char* name() const override { return "Binary Diff"; }
    void render(AppContext& ctx) override;

private:
    struct FileIdentity {
        uint64_t size = 0;
        uint64_t writeTime = 0;
        uint64_t fileIndex = 0;
        uint32_t volumeSerial = 0;
        bool valid = false;
    };

    void openInto(bool leftSide); // file dialog + identity only; worker owns loading
    void computeDiff(const AppContext* ctx = nullptr); // enqueue/replaces a background comparison request
    void cancelDiff();
    void invalidateComparison(); // retire visible results/proposals when inputs change
    void pumpDiffResult();       // apply an owned result on the render thread
    void workerLoop(std::stop_token stop);
    static bool queryFileIdentity(const std::string& path, FileIdentity& out);
    static bool sameIdentity(const FileIdentity& a, const FileIdentity& b);
    void gotoRegion(int idx);    // select region idx and scroll both panes to it
    void ensureDecoders();       // (re)build a per-binary decoder when its arch changes
    void renderDiffAsm();        // side-by-side disassembly of the selected region
    void renderLoadZone(AppContext& ctx);
    void renderSemantic(AppContext& ctx);
    void applySelectedSemanticTransfers(AppContext& ctx);
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

    enum class DiffPhase : uint8_t {
        Idle,
        LoadingLeft,
        LoadingRight,
        ComparingBytes,
        ComparingSections,
        BuildingSemanticLeft,
        BuildingSemanticRight,
        MatchingSemantics,
        Complete,
        Cancelled,
        Failed,
    };
    static const char* phaseName(DiffPhase phase);

    struct DiffJob {
        struct MetadataSnapshot {
            uint64_t hash = 0;
            std::vector<std::pair<uint64_t, std::string>> names;
            std::vector<std::pair<uint64_t, std::string>> comments;
            std::vector<std::pair<uint64_t, std::string>> prototypes;
            std::vector<uint64_t> bookmarks;
        } activeMetadata;
        uint64_t epoch = 0;
        std::string leftPath;
        std::string rightPath;
        FileIdentity leftIdentity;
        FileIdentity rightIdentity;
        bool sectionAware = false;
        bool semantic = false;
    };

    struct DiffResult {
        uint64_t epoch = 0;
        FileIdentity leftIdentity;
        FileIdentity rightIdentity;
        std::vector<DiffRow> diffs;
        std::vector<DiffRegion> regions;
        std::vector<SecDiff> sections;
        uint64_t totalDiff = 0;
        uint64_t sectionTotalDiff = 0;
        size_t sectionUnmatched = 0;
        BinaryFile leftBinary;
        BinaryFile rightBinary;
        std::optional<SemanticImage> semanticLeft;
        std::optional<SemanticImage> semanticRight;
        SemanticDiffResult semanticDiff;
        bool semanticRequested = false;
        std::string semanticError;
        std::string semanticWarning;
        std::string error;
    };

    BinaryFile           left_;
    BinaryFile           right_;
    std::string          selectedLeftPath_;
    std::string          selectedRightPath_;
    FileIdentity         leftIdentity_;
    FileIdentity         rightIdentity_;
    std::vector<DiffRow> diffs_;
    bool                 computed_ = false;
    size_t               totalDiff_ = 0;
    char                 jump_[32] = "";

    // Section-aware alignment: when on, diffs are computed per matching section
    // (by name, falling back to RVA) instead of by flat file offset, so an
    // inserted/removed byte early in the file doesn't cascade every later
    // section into a false "all-different".
    bool                    sectionAware_ = false;
    bool                    semanticMode_ = false;
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
    std::string                    leftDisError_, rightDisError_;

    std::optional<SemanticImage>   semanticLeft_;
    std::optional<SemanticImage>   semanticRight_;
    SemanticDiffResult             semanticDiff_;
    bool                           semanticComputed_ = false;
    std::string                    semanticError_;
    std::string                    semanticWarning_;
    int                            semanticSelectedMatch_ = -1;
    int                            semanticSelectedHunk_ = -1;
    std::vector<bool>              semanticProposalSelected_;
    size_t                         semanticProposalSelectionCount_ = 0;
    DocumentResultIdentity         semanticTransferTarget_;
    std::string                    semanticTransferStatus_;
    char                           semanticFilter_[128] = "";
    std::string                    appliedSemanticFilter_;
    bool                           semanticChangesOnly_ = false;
    bool                           semanticFilterDirty_ = true;
    std::vector<size_t>             semanticVisibleMatches_;
    std::vector<size_t>             semanticVisibleAdded_;
    std::vector<size_t>             semanticVisibleRemoved_;

    // A persistent worker consumes only paths/identities and reloads files into
    // worker-owned BinaryFile instances. It never borrows the render thread's
    // byte buffers. New requests replace pending work; epochs reject stale work.
    std::mutex                     workerMutex_;
    std::condition_variable        workerCv_;
    std::optional<DiffJob>         pendingJob_;
    std::optional<DiffResult>      readyResult_;
    std::atomic<uint64_t>          desiredEpoch_{0};
    std::atomic<bool>              diffRunning_{false};
    std::atomic<DiffPhase>         diffPhase_{DiffPhase::Idle};
    std::atomic<uint64_t>          diffProgress_{0};
    std::atomic<uint64_t>          diffProgressTotal_{0};
    std::string                    diffError_;
    std::jthread                    worker_; // last: all synchronization state exists before launch
};

} // namespace ds
