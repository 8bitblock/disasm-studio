#pragma once
#include "ITab.h"
#include "BinaryViewValueOrigin.h"
#include "BinaryViewStringTrace.h"
#include "../Core/ProcessManager.h"    // ModuleInfo (Functions sub-tab)
#include "../Core/SymbolService.h"     // asynchronous DbgHelp / PDB ownership
#include "../Core/DocumentContext.h"   // one bounded navigation history per document
#include "../Core/TypeSystem.h"
#include "../Core/XrefIndex.h"         // whole-program cross-reference index (Xrefs tab)
#include "../Core/AlgoScan.h"          // AlgoMatch (Algorithms sub-tab / K_Intent results)
#include "../Core/CFG.h"               // ControlFlowGraph (cached CFG graph view)
#include "../Ui/GraphViewport.h"
#include "../Core/Decompiler.h"        // DecompResult (pseudocode + per-line VA map)
#include "../Core/AnalysisJobs.h"      // ListingLayout / ListingRowType
#include "../Core/AddressInspector.h"  // validity-bearing FILE/LIVE address projection
#include "../Core/MemoryValueHint.h"  // decoder-width numeric memory observations
#include "../Core/LivePatchOriginal.h" // session-only live-patch rollback bytes
#include "../Core/RegisterEdit.h"      // bounded register value/text editor input
#include "../Core/Backtrace.h"         // exact paused stack ownership and caller evidence
#include "../Core/InvestigationIndex.h" // immutable unified-omnibox snapshots
#include "../Core/BinaryOverview.h" // bounded, evidence-bearing investigation starts
#include "../Core/ListingVirtualIndex.h" // 64-bit Fenwick virtual-row mapper
#include "../Core/PatchRefresh.h"     // coalesced post-patch semantic refresh
#include "../Core/PatchedImage.h"     // named patch-set composition/comparison
#include "../Core/FuncAnnotate.h"      // FuncAnnotations ("Annotations" lower tab + inline notes)
#include "../Core/GameContext.h"       // game/crackme workflow context panel
#include "../Core/CrackmeTriage.h"     // bounded offline endpoint/server trail
#include "../Core/AuthorizationExperiment.h" // checked register-only predicate experiment
#include "../Core/JvmAnnotate.h"       // JvmMethodAnalysis ("Java" lower tab + inline stack effects)
#include "../Core/Synthesis.h"         // SynthResult ("Synthesis" lower tab)
#include "../Core/PathExplore.h"       // PathTree ("Path Explorer" lower tab)
#include "../Core/Cond.h"              // CondOperand (compiled Watch expressions)
#include "../Core/TracePlan.h"         // exact, gap-preserving native trace coverage
#include <cstdint>
#include <deque>
#include <list>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

struct ImDrawList;

namespace ds {

// Binary View: the central workspace. Three synchronized views (assembly,
// pseudocode, raw bytes) plus a side panel of bookmarks / functions / strings,
// byte-pattern search, and lower sub-tabs for breakpoints / notes / results /
// hotkeys.
class BinaryViewTab final : public ITab {
public:
    // A Binary View is permanently bound to one stable static-document owner.
    // The default-invalid form is retained only as a fail-closed compatibility
    // seam while the App shell migrates to BinaryViewHostTab.
    explicit BinaryViewTab(DocumentId documentId = {}) : documentId_(documentId) {}

    const char* name() const override { return "Binary View"; }
    void render(AppContext& ctx) override;
    DocumentId documentId() const { return documentId_; }
    void showBacktrace();

    // Symbol entries exposed to the command palette: address + display name +
    // a pre-lowercased copy for fuzzy matching. Backed by the signature-cached
    // goto-symbol index (rebuilt only when the target/process changes).
    struct SymEntry {
        uint64_t addr;
        std::string name;
        std::string lower;
        bool live = false; // runtime address (live module export) vs file/project VA
    };
    const std::vector<SymEntry>& paletteSymbols(AppContext& ctx);

    // Retained menu/palette actions carry their original document and address
    // space; invoking one after a document/image/session change fails closed.
    enum class ContextAction { Rename, Comment, Bookmark, ShowLive, ShowStatic, RunToCursor };
    struct ContextActionTarget {
        DocumentId document{};
        uint64_t imageGeneration = 0;
        uint64_t imageRevision = 0;
        DecoderConfig decoder{};
        uint64_t address = 0;
        bool valid = false;
        bool live = false;
        bool instruction = false;
        DebugTargetIdentity liveOwner{};
        uint64_t liveModules = 0;
    };
    ContextActionTarget cursorActionTarget(AppContext& ctx) const;
    bool contextualActionAvailable(AppContext& ctx, ContextAction action,
                                   const ContextActionTarget& target,
                                   std::string& reason) const;
    bool dispatchContextAction(AppContext& ctx, ContextAction action,
                               const ContextActionTarget& target);

    // Called while this document is still AppContext's active static owner.
    // Mirrors all tab-local analyst state before DocumentManager serializes it.
    // Closing additionally joins this child's PDB/symbol worker and retires its
    // token-owned live pattern requests before retained state may be released.
    bool prepareDocumentTransition(AppContext& ctx, bool closing,
                                   std::string& error);
    void retireDocument(AppContext& ctx);
    bool hasUnsavedTypeDraft() const { return typeDraftDirty_; }
    const std::string& typeDraftName() const { return typeDraft_.name; }
    bool saveTypeDraft(AppContext& ctx, bool persist, std::string& error);
    void discardTypeDraft(AppContext& ctx);

    // Incrementally copy the UI-owned analysis/live state into an immutable
    // investigation snapshot.  The bounded slice is intentionally callable even
    // while another tab is active: App uses it to keep Ctrl+K ready without ever
    // copying or searching the whole corpus on the render thread.
    void advanceInvestigationSnapshot(
        AppContext& ctx,
        const std::vector<InvestigationRecentQuery>& recentQueries,
        uint64_t recentRevision,
        size_t recordBudget = 768);
    std::shared_ptr<const InvestigationSnapshot> investigationSnapshot() const {
        return investigationPublished_;
    }
    uint64_t investigationSnapshotGeneration() const {
        return investigationPublishedGeneration_;
    }
    bool investigationSnapshotBuilding() const { return investigationBuilding_; }

private:
    bool documentMatches(const AppContext& ctx) const;
    bool synchronizeDocumentImage(AppContext& ctx);
    void retireUnloadedImage(AppContext& ctx);
    void retireChangedLiveSession(AppContext& ctx);
    void updateAuthorizationExperiment(AppContext& ctx,
                                       const struct DbgSnapshot& snap);

    struct ListRow;
    void renderWelcome(AppContext& ctx);
    void applyWorkflow(AppContext& ctx, int preset);
    void renderWorkflowContext(AppContext& ctx, bool compact = false);
    void renderEvidenceInspector(AppContext& ctx, bool collapsed, bool widthConstrained = false);
    void renderEvidenceInspectorContent(AppContext& ctx, bool popup = false);
    ValueOriginViewState valueOrigin_;
    bool valueOriginCurrent(AppContext& ctx) const;
    bool valueOriginHighlights(AppContext& ctx, uint64_t va) const;
    void adoptValueOriginResult(AppContext& ctx, const AnalysisResult& result);
    void requestValueOrigin(AppContext& ctx, const std::string& registerName);
    void renderValueOriginInspector(AppContext& ctx);
    StringTraceViewState stringTrace_;
    bool stringTraceCurrent(AppContext& ctx) const;
    void requestStringActionTrace(AppContext& ctx, uint64_t va, const std::string& text, bool live);
    void advanceStringActionTrace(AppContext& ctx);
    void queueStringActionDependencies(AppContext& ctx, uint32_t kinds);
    void adoptStringActionTraceResult(AppContext& ctx, const AnalysisResult& result);
    void renderStringActionTrace(AppContext& ctx);
    void selectRepresentation(AppContext& ctx, int view);
    void renderTypeWorkbench(AppContext& ctx);
    void renderTypedLocation(AppContext& ctx, uint64_t va);
    void renderOverview(AppContext& ctx);
    std::vector<RecentEntry> welcomeRecents_; // at most seven displayed targets
    double welcomeRecentsRefresh_ = -1.0;
    int welcomeLastFrame_ = -1;
    std::string welcomeOpenError_;
    void renderAssembly(AppContext& ctx);          // dispatcher: full-program or windowed
    void renderListingToolbar(AppContext& ctx, bool live); // bounded view actions; execution stays in the shell
    void renderAssemblyWindow(AppContext& ctx);    // ~256 instructions around the cursor
    void renderAssemblyFull(AppContext& ctx);      // entire program, clipper-rendered
    void buildFullListing(AppContext& ctx);        // queue an off-thread listing plan/build
    uint64_t listingSig(AppContext& ctx) const;    // cache key for listRows_ (image/funcs/strings/arch/engine)
    std::shared_ptr<const ListingLayout> listingLayoutSnapshot() const;
    void listingLayoutChanged(AppContext& ctx);    // persist + queue newest immutable snapshot
    void renderListingRegionHeader(AppContext& ctx, const ListRow& row);
    void renderListingDataRow(AppContext& ctx, const ListRow& row);
    void renderAsmFuncHeader(AppContext& ctx, uint64_t addr);
    void renderAsmLocationHeader(uint64_t addr);
    void renderAsmRow(AppContext& ctx, Instruction in, const struct DbgSnapshot& snap,
                      const std::string& hoverTok, std::string& nextHoverTok,
                      bool autoScrollHere, bool boundaryExact);
    void selectRange(AppContext& ctx, uint64_t a, uint64_t b);             // retain selected displayed instructions
    void assemblyRowSelection(AppContext& ctx, const Instruction& in, bool live,
                              const std::vector<Instruction>* liveInstructions,
                              bool addressActivated, const char* popupId);
    void asmSelectionMenu(AppContext& ctx, const struct DbgSnapshot& snap); // batch actions over selVAs_ (static listing)
    void liveSelectionMenu(AppContext& ctx, const struct DbgSnapshot& snap); // batch actions over selVAs_ (live listing)
    void emitInstrCopyMenu(const Instruction& in, Arch arch, bool shortcuts = true);
    void copyAssemblyBytes(AppContext& ctx, const DbgSnapshot& snap,
                           bool live, bool wildcard, bool cArray = false);
    void assemblyCopyShortcut(AppContext& ctx, const DbgSnapshot& snap, bool live);
    bool liveInstructionForCopy(AppContext& ctx, const DbgSnapshot& snap,
                                uint64_t address, Instruction& out, std::string& error);
    void stepAsmCursor(AppContext& ctx, int delta);                         // exact on-demand page stepping
    void drawAsmArrows(float x0, float y0, float x1, float y1,
                       ImDrawList* listingDrawList = nullptr); // branch arrows in the scrolling table's drawlist
    void revertPatchAt(AppContext& ctx, uint64_t va,
                       size_t exactIndex = (std::numeric_limits<size_t>::max)()); // restore one recorded patch
    bool restoreSavedPatches(AppContext& ctx, bool announce = false);
    bool forgetUnrestoredPatch(AppContext& ctx, size_t index);
    bool transitionPatchSetState(AppContext& ctx,
                                 std::vector<PjPatch> desiredPatches,
                                 std::vector<PjPatchSet> desiredSets,
                                 const char* action,
                                 DocumentLiveImageCommit liveImageCommit =
                                     DocumentLiveImageCommit::InvalidateMappedIdentity,
                                 bool exactLiveStateChanged = false,
                                 bool announce = true);
    void invalidatePatchSetImage(AppContext& ctx);
    void normalizePatchDestination(const ProjectState& project);
    bool renderPatchDestinationCombo(const ProjectState& project,
                                     const char* label);
    void renderPatchSetsPanel(AppContext& ctx);
    void renderLiveAssembly(AppContext& ctx);
    void renderLiveListing(AppContext& ctx, const struct DbgSnapshot& snap, uint64_t start);
    void renderLivePseudocode(AppContext& ctx, const struct DbgSnapshot& snap, uint64_t start);
    void renderRegisterBox(AppContext& ctx, const struct DbgSnapshot& snap);
    void renderLiveSearchPopup(AppContext& ctx);
    void renderPatchPopup(AppContext& ctx);
    void renderAnalystOverridePopup(AppContext& ctx);
    struct PreparedPatchLiveWrite {
        bool liveRequested = false;
        DebugTargetIdentity owner{};
        uint64_t fileVA = 0;
        uint64_t runtimeVA = 0;
        std::vector<uint8_t> observed;
    };
    struct PatchApplyOutcome {
        bool staticCommitted = false;
        bool liveRequested = false;
        bool liveComplete = false;
        size_t liveBytesWritten = 0;
    };
    bool applyPatchBytes(AppContext& ctx, uint64_t va, std::vector<uint8_t> bytes,
                         uint32_t origLen, bool padNop,
                         const PreparedPatchLiveWrite* preparedLive = nullptr,
                         PatchApplyOutcome* outcome = nullptr,
                         bool addressIsExplicitlyStatic = false); // record patch + optional exact live write
    void openAnalystOverrideEditor(AppContext& ctx, uint64_t va, uint32_t defaultSize);
    // Canonical (file-VA) key a patch is stored under, translating a runtime VA
    // from the live listing back to file space when attached under ASLR.
    uint64_t patchKeyFor(AppContext& ctx, uint64_t va);
    std::string buildSignature(AppContext& ctx, uint64_t lo, uint64_t hi,
                               bool live, bool wildcard,
                               const DbgSnapshot* liveSource = nullptr); // instruction span -> "48 8B ?? .." pattern
    void renderXrefPopup(AppContext& ctx);
    void renderPinnedXrefs(AppContext& ctx);
    bool followXrefSource(AppContext& ctx, size_t hitIndex);
    void startXrefSearch(AppContext& ctx, uint64_t target, bool liveTarget);
    void updateStaticXrefSearch(AppContext& ctx);
    void analyzeAllModules(AppContext& ctx);   // read every module's image (off-thread) + analyze each
    bool ensureXrefReady(AppContext& ctx);     // true if the index is current; else kicks an off-thread K_Xref build
    bool adoptStaticXrefResult(AppContext& ctx, const AnalysisResult& result);
    uint64_t xrefSig(AppContext& ctx) const;   // content signature the xref index is cached by
    void renderXrefsTab(AppContext& ctx);      // "Xrefs" lower sub-tab: who references the cursor / its function
    void exportAnalysis(AppContext& ctx);      // File > Export Analysis: write Markdown/HTML report
    void openCodeExport(AppContext& ctx, CodeExportFormat format,
                        bool explicitFunction = false, uint64_t functionVA = 0);
    void startCodeExport(AppContext& ctx);      // snapshot names/functions + choose path + queue worker
    void renderCodeExportPopup(AppContext& ctx);// options, progress/cancel, completion result
    std::string decompileFunctionText(AppContext& ctx, uint64_t fnStart, uint32_t fnSize); // structured pseudo-C for one fn
    void requestFunctionDecompile(AppContext& ctx, uint64_t fnStart, uint32_t fnSize,
                                  size_t availableBytes, bool boundedRange); // queue named/signature-aware worker decompile
    std::string symbolFor(AppContext& ctx, uint64_t addr, bool live = false); // explicit FILE/LIVE address ownership
    void ensureSymbolSession(AppContext& ctx, bool live);
    void renderPdbSymbolsTab(AppContext& ctx);
    void renderAddressInspectorTab(AppContext& ctx);
    ContextActionTarget contextActionTarget(AppContext& ctx, uint64_t address,
                                            bool live, bool valid = true,
                                            bool instruction = true) const;
    void renderContextActionMenu(AppContext& ctx, const ContextActionTarget& target,
                                  bool annotations = true, bool debugging = true);
    uint64_t investigationSourceSignature(AppContext& ctx,
                                          uint64_t recentRevision) const;
    void beginInvestigationSnapshot(AppContext& ctx, uint64_t signature);
    // Per-stop memo key (register snapshot + liveGen_ + state). Shared by the live-view
    // caches (ptrDescCache_, strCmtCache_) so they invalidate together on step / re-stop / edit.
    uint64_t liveStopKey(const struct DbgSnapshot& snap) const;
    // Live view: describe what a register/stack value points to (string / symbol / ->string),
    // or "" if it isn't a meaningful pointer. Reads debuggee memory; only valid while paused.
    std::string describePointer(AppContext& ctx, const struct DbgSnapshot& snap, uint64_t v);
    // Best-effort main-module base used only to order modules in a live string
    // scan. Cross-space navigation/state always uses the exact helpers below.
    uint64_t liveMainBase(AppContext& ctx);                  // runtime base of the attached main module, 0 if unknown
    // Translate a persisted/static file VA only when the attached process has an
    // exact same-name module of matching x86/x64 bitness and the RVA is inside
    // that module.  Static breakpoints stay pending when this proof is absent.
    bool staticBreakpointRuntimeVA(AppContext& ctx, uint64_t fileVA, uint64_t& runtimeVA) const;
    // Checked inverse mapping through the same exact image/session proof. This
    // additionally requires the resulting FILE VA to be backed by the document.
    bool exactLiveToStaticVA(AppContext& ctx, uint64_t liveVA, uint64_t& fileVA) const;
    void armPendingStaticBreakpoints(AppContext& ctx);
    void restoreSavedBreakpointBoundaries(AppContext& ctx);
    void resetStaticBreakpointArming(uint64_t fileVA);
    bool setBreakpointEnabled(AppContext& ctx, uint64_t projectKey, bool file,
                              uint64_t runtimeVA, bool enabled);
    void markStaticBreakpointBoundariesChanged() { staticBreakpointSweepDirty_ = true; }
    const char* staticBreakpointStatus(AppContext& ctx, uint64_t fileVA,
                                       std::string& detail) const;
    void renderCallStack(AppContext& ctx);
    void renderStackTab(AppContext& ctx);   // annotated live stack dump (RSP/RBP, symbols, strings)
    void computeCallStack(AppContext& ctx, const struct DbgSnapshot& snap);
    bool navigateCallFrame(AppContext& ctx, size_t index, bool callCandidate = false);
    std::string copyBacktrace(const struct DbgSnapshot& snap) const;
    void renderGotoPopup(AppContext& ctx);
    void buildSymbolIndex(AppContext& ctx);
    void startTextSearch(AppContext& ctx);                      // search disassembly text
    void pumpTextSearch(AppContext& ctx);                       // bounded per-frame search slice
    void renderTextSearchPopup(AppContext& ctx);
    // Render text as hover-highlightable tokens: matches of `hl` get a background;
    // a hovered word token is written to `nextHover` (for next frame's highlight).
    void renderHoverTokens(const char* s, unsigned int col, const std::string& hl, std::string& nextHover);
    void renderPseudocode(AppContext& ctx);
    void renderDecompiler(AppContext& ctx);   // side-by-side decompiled pseudo-C | synced asm pane
    void renderHex(AppContext& ctx);
    void hexCommitByte(AppContext& ctx, uint64_t off, uint8_t value);   // route an edit into the patch system
    void renderGraph(AppContext& ctx);
    // Execution-coverage control and display. Site discovery walks the immutable
    // listing index in bounded slices; no whole-image CFG build occurs in render.
    void beginTraceSeedPlan(AppContext& ctx);
    void cancelTraceSeedPlan(AppContext& ctx, bool stopDebuggerTrace);
    void advanceTraceSeedPlan(AppContext& ctx);
    void refreshTraceDisplay(AppContext& ctx);
    bool traceFileExecuted(uint64_t va) const;
    bool traceLiveExecuted(uint64_t va) const;
    bool traceGraphBlockExecuted(uint64_t start, uint64_t end) const;
    void renderCallGraph(AppContext& ctx);             // callers/callees around the cursor fn
    void buildCallGraph(AppContext& ctx);              // cached call edges between functions (UI-thread fallback)
    bool ensureCallGraphReady(AppContext& ctx);        // true if current; else kicks an off-thread K_CallGraph build
    std::string guessSignature(AppContext& ctx, uint64_t fnStart, uint32_t fnSize); // best-effort
    // Resolve a constant data address to a decompiler token (quoted string literal,
    // import/global name), or "" if not meaningful. `live` reads process memory.
    std::string dataRefToken(AppContext& ctx, uint64_t va, bool live);
    MemoryValueHint memoryValueHint(AppContext& ctx, const Instruction& in,
                                    const DbgSnapshot* live = nullptr);
    bool isNoreturnTarget(AppContext& ctx, uint64_t fileVA) const;
    ResolvedJumpTable resolveJumpTable(AppContext& ctx, const Instruction& in); // switch tables
    void renderSidePanel(AppContext& ctx);
    void renderSectionsTab(AppContext& ctx);            // PE header + per-section visibility/fold controls
    void renderLowerTabs(AppContext& ctx, bool headerOnly);
    void renderBreakpoints(AppContext& ctx);
    size_t breakpointDisplayCount(AppContext& ctx) const;
    void addBreakpointAtCursor(AppContext& ctx);
    void renderExportsTab(AppContext& ctx);             // complete PE EAT browser (aliases/ordinals/forwarders)
    void renderResourcesTab(AppContext& ctx);           // PE resource-directory browser (tree + decode/preview + save)
    void buildResourcePreview(AppContext& ctx);         // (re)build the cached preview for resourceSel_
    // Advanced analysis features (synchronous on-demand, like the decompiler).
    void runSynthesis(AppContext& ctx, uint64_t lo, uint64_t end);   // synthesize a region
    void renderSynthesisTab(AppContext& ctx);                        // results lower tab
    void openHotPatch(AppContext& ctx, uint64_t siteVA, uint32_t origLen); // open editor
    void applyHotPatch(AppContext& ctx);                             // compile + place + patch
    void renderHotPatchTab(AppContext& ctx);                         // editor lower tab
    void runPathExplore(AppContext& ctx, uint64_t rootVA);           // explore from here
    void renderPathExplorerTab(AppContext& ctx);                     // path tree lower tab
    void renderCommentPopup(AppContext& ctx);   // edit address -> comment
    void renderRenamePopup(AppContext& ctx);    // edit address -> name
    void invalidateNameDependentCaches();       // user/discovered names changed: refresh picker/pseudocode/etc.
    void renderCondPopup(AppContext& ctx);      // edit address -> breakpoint condition
    void loadProjectState(AppContext& ctx);     // ctx.staticProject() -> tab members (on open)
    void saveProjectState(AppContext& ctx);     // tab members -> ctx.staticProject() (each frame)
    std::string annName(AppContext& ctx, uint64_t addr);  // user rename for addr, or ""
    void runByteSearch(AppContext& ctx);
    // Queue the shared masked-pattern worker for a captured debugger session.
    // `popup` selects the Live Search modal rather than the Navigator results.
    void startLivePatternSearch(AppContext& ctx, std::string_view query, int kind,
                                DebugTargetIdentity owner, bool popup);
    void analyzeFunctions(AppContext& ctx);            // run FunctionAnalyzer -> functions_ list
    void guessFunctionNames(AppContext& ctx);          // heuristically name sub_ functions (read_file, j_CreateFileW, ...)
    void scanStrings(AppContext& ctx);                 // ASCII/UTF-8 + UTF-16LE -> strings_ list
    void onBinaryLoaded(AppContext& ctx);              // re-home cursor to entry point + auto-analyze
    void liveNavigate(uint64_t va);    // enter live view, set runtime cursor, record history
    void navigateTo(uint64_t va);      // unified: move cursor + push back/forward history
    void navigateToStaticView(uint64_t va, DocumentView view = DocumentView::Assembly);
    void navigateToFileOffset(AppContext& ctx, uint64_t offset);
    void selectFileOffset(AppContext& ctx, uint64_t offset);
    void restoreNavigationLocation(const DocumentLocation& location);
    void updateNavigationRepresentation();
    bool canNavigateBack() const;
    bool canNavigateForward() const;
    void setStaticCursor(uint64_t va, bool valid = true); // install + retain a FILE-space focus
    void setLiveCursor(uint64_t va, bool valid = true);   // install a debugger-session focus
    void restoreStaticCursor(AppContext& ctx); // replace a live VA before rendering/persisting FILE views
    void restoreLiveCursor(const struct DbgSnapshot& snap); // replace a FILE VA before rendering Live
    // Navigate to a FILE-space address from a side panel / list (functions, bookmarks,
    // imports, ...): records history, and in the live view translates to the runtime VA.
    void gotoStatic(AppContext& ctx, uint64_t fileVA);
    void gotoExportTarget(AppContext& ctx, const BinaryFile::Export& ex); // code -> Assembly, mapped data -> Hex
    void gotoResourceData(const BinaryFile::Resource& r); // navigate the Hex view to a resource's bytes
    void navBack();                    // step back in navigation history
    void navForward();                 // step forward in navigation history
    void toggleBreakpoint(AppContext& ctx, uint64_t va);   // SW breakpoint at va (+ live debugger)

    struct Bookmark  { uint64_t address; std::string label; };
    struct Strng {
        uint64_t address;
        std::string text;
        bool wide = false;
        bool textTruncated = false;
    };
    struct Func      {
        uint64_t address;
        std::string name;
        uint32_t size;
        bool guessed = false;
        bool isExport = false; // authoritative discovery name; FunctionNamer must preserve it
        bool analystDefined = false;
        bool noreturnValid = false;
        bool noreturn = false;
        uint8_t analystMode = 0; // persisted metadata: 0 unspecified, 1 ARM, 2 Thumb
        std::string callingConvention;
        std::string prototype;
        std::vector<FunctionChunk> chunks;
        bool ownershipTruncated = false;
        FunctionSeedKind seedKind = FunctionSeedKind::Prologue;
        FunctionBoundaryConfidence boundaryConfidence = FunctionBoundaryConfidence::Heuristic;

        bool contains(uint64_t va) const {
            if (va == address) return true;
            if (!chunks.empty()) {
                for (const FunctionChunk& chunk : chunks)
                    if (chunk.size && va >= chunk.address && va - chunk.address < chunk.size)
                        return true;
                return false;
            }
            return size && va >= address && va - address < size;
        }
    };
    struct CallFrame {
        uint64_t pc = 0, frameSp = 0;
        std::string name;
        uint64_t stackPtr = 0;
        BacktraceCallCandidate callCandidate;
        bool candidate = false;
        std::string module;
    };

    uint64_t cursorVA_  = 0;     // current focus address (VA 0 is valid when cursorValid_)
    bool     cursorValid_ = false;
    bool     cursorLive_ = false; // cursorVA_ is a debugger-session VA, independent of selected view
    uint64_t staticCursorVA_ = 0; // last mapped FILE focus, retained while browsing Live
    bool     staticCursorValid_ = false;
    int      mainView_  = 0;     // 0=asm 1=pseudo 2=hex 3=graph 4=live 5=callgraph 7=overview (6 is legacy)
    int      workflowPreset_ = 0;
    DocumentLocation viewPins_[8]{};
    uint64_t viewPinsImage_ = 0;
    bool     focusTypesTab_ = false;
    bool     focusResourcesTab_ = false;
    uint32_t navigatorOptionalMask_ = 0;
    bool     analysisQueueCollapsed_ = false;
    bool     evidenceInspectorCollapsed_ = false;
    float    evidenceInspectorW_ = 252.0f;
    TypeDefinition typeDraft_;
    uint64_t typeDraftImage_ = 0;
    uint64_t typeDraftGeneration_ = 0;
    bool typeDraftDirty_ = false;
    std::string typeStatus_;
    char typeFilter_[96]{};
    char typeApplicationName_[97]{};
    BinaryOverview overview_;
    uint64_t overviewImageSerial_ = 0;
    uint64_t overviewImageRevision_ = 0;
    uint64_t overviewEpoch_ = 0;
    std::shared_ptr<const std::vector<FuncResult>> overviewFunctions_;
    int      overviewSideRequest_ = 0; // 1=Functions, 2=FILE Strings, 3=Bookmarks
    bool     overviewImportsRequest_ = false;
    bool     overviewMoreLeads_ = false;

    // IDE workbench layout: one active analysis viewport | one right inspector, over
    // a full-width tool drawer. The inspector width and expanded drawer height are
    // retained per document; layoutScale_ keeps dragged dimensions stable across
    // live per-monitor DPI transitions.
    bool     dockInitDone_    = false;   // retained (unused by the fixed layout)
    float    layoutScale_     = 0.0f;    // physical scale currently applied to retained dimensions
    float    inspectorW_  = 0.0f;        // 0 = choose a viewport-relative 72/28-ish default
    bool     inspectorUserSized_ = false; // keep the 72/28 default responsive until the splitter is dragged
    float    bottomDockH_ = 168.0f;      // compact mockup detail drawer
    bool     lowerDockCollapsed_ = false; // retain tab-bar-only state per document view
    bool     sideAdvancedMode_ = false;  // primary navigator tabs vs. secondary image tools
    bool     sideTabsInitialized_ = false; // select Functions on the first primary render
    bool     lowerAdvancedMode_ = false; // concept core drawer vs. additional specialist tools
    // Sub-view pop-out: pop a SPECIFIC main-view rendering (CFG / pseudocode) into its
    // own OS window (multi-viewport). Orthogonal to panel docking; closing it docks back.
    bool     graphPoppedOut_  = false;   // Graph (CFG) main view
    bool     pseudoPoppedOut_ = false;   // Pseudocode main view

    // Drag-resizable widths for the two in-panel sub-splits (VSplitter); scaled for
    // HiDPI in the ctor-equivalent first use. Session-only (not persisted).
    float    regsSplitW_ = 360.0f;       // Registers | Stack split (lower Registers tab)
    float    liveBoxW_   = 252.0f;       // Live listing | register-box split
    // Decompiler view: pseudo-C pane | synced asm pane split, and the asm VA hovered
    // (or whose pseudo line is hovered) so the two panes cross-highlight each other.
    float    decompSplitW_ = 0.0f;       // unset until first use; then retained pseudo pane width
    uint64_t decompHoverVA_ = 0;         // VA cross-highlighted between the two panes
    bool     decompHoverValid_ = false;

    // Assembly Address/Bytes/Instruction cells: click = single, drag/Shift+click
    // = range from the anchor, Ctrl+click = toggle one line.
    std::unordered_set<uint64_t> selVAs_;
    uint64_t                     selAnchorVA_ = 0;
    bool                         selAnchorValid_ = false;
    int                          selView_ = -1;   // which listing (0=static,4=live) owns the current selection
    bool                         assemblySelectionDragging_ = false;
    int                          assemblySelectionDragView_ = -1;
    double                       assemblySelectionMouseDownTime_ = -1.0;
    uint64_t                     assemblySelectionDragLastVA_ = 0;

    // Full-program listing: a worker-built, clipper-friendly row index containing
    // instruction/function/string rows plus modeled section/header/data-directive
    // rows. The first four fields mirror legacy rows; the remainder mirror ListRowR.
    struct ListRow {
        uint64_t       addr = 0;
        bool           divider = false;
        bool           strData = false;
        int            strIdx = -1;
        ListingRowType type = ListingRowType::Normal;
        uint32_t       sectionIndex = kListingPeHeaderIndex;
        uint16_t       dataSize = 0;
        bool           folded = false;
        uint64_t       aux = 0;
        CodeDataKind   dataKind = CodeDataKind::Data;
        uint8_t        dataWidth = 1;
        uint32_t       codeRegion = 0;
    };
    struct CodePageRow {
        ListRow row;
        int     insnIndex = -1; // -1 for function/loc labels
    };
    struct CodePageCache {
        std::vector<Instruction> insns;
        std::vector<CodePageRow> rows;
        uint64_t                 lastUse = 0;
        bool                     boundaryExact = true;
    };
    std::vector<ListRow> listRows_;
    bool                 listBuilt_     = false;
    uint64_t             listSig_       = 0;
    uint64_t             listingCodeBytes_ = 0;
    uint64_t             listingCodePages_ = 0;
    ListingVirtualIndex  listingRowsIndex_;
    std::unordered_map<size_t, CodePageCache> codePageCache_; // descriptor index -> decoded page
    // Only proven checkpoints live here: section/function roots or values
    // propagated from another proven checkpoint. Ordered lookup finds the nearest
    // safe predecessor without ever manufacturing an unknown page-front zero.
    std::map<size_t, uint32_t> codePagePrefixSkip_;
    // Descriptor checkpoints seeded directly by an authoritative/reconciled
    // function chunk (or the loader entry).  Derived predecessor propagation may
    // meet one of these roots, but must never overwrite it with a conflicting
    // continuation from a different instruction stream.
    std::unordered_set<size_t> codePageRootCheckpoints_;
    // Far random-access pages are painted from a bounded local alignment guess.
    // They remain provisional until an exact section/function chain reconciles
    // them. Trace never trusts them; an explicit breakpoint/patch action may
    // accept only its displayed address as analyst authority.
    std::unordered_set<size_t> codePagePrefixEstimated_;
    std::unordered_map<uint32_t, size_t> codePageRegionFirst_;
    uint64_t             codePageUseClock_ = 0;
    uint64_t             codePageCacheKey_ = ~0ull;
    // Owner -> exact decode start. The value prevents an older completion for
    // the same descriptor from retiring a newer request after topology churn.
    std::unordered_map<size_t, uint64_t> codePagePrefixPending_;
    uint64_t             codePagePrefixPendingEpoch_ = 0;
    uint64_t             listingTopologyGeneration_ = 1;
    // Function discovery publishes before its matching listing topology. While
    // that replacement is in flight, old descriptor checkpoints are display-only.
    bool                 listingTopologyPending_ = false;
    ListingBoundaryAuthority listingBoundaryAuthority_;
    std::unordered_map<uint64_t, ListingInstructionSnapshot> listingSelectedInstructions_;
    ListingInstructionSnapshot listingCursorInstruction_;
    size_t listingSelectedBytes_ = 0;
    uint64_t listingSelectionVersion_ = 0;
    uint64_t listingSelectionCheckKey_ = ~uint64_t{0};
    std::vector<Instruction> listingSelectionChecked_;
    std::string listingSelectionError_;
    bool listingSelectionCanNop_ = false;
    void rememberListingSelection(AppContext& ctx);
    bool decodeListingActionInstruction(AppContext& ctx, uint64_t address,
                                        Instruction& instruction, std::string& error) const;
    bool listingActionInstruction(AppContext& ctx, uint64_t address,
                                  Instruction& instruction, std::string& error);
    bool validateListingInstructionBoundary(AppContext& ctx, uint64_t address, std::string& error);
    bool restoreListingInstructionBoundary(AppContext& ctx, uint64_t address, std::string& error);
    bool beginStaticInstructionPatch(AppContext& ctx, uint64_t address);
    bool beginLiveInstructionPatch(AppContext& ctx, const DbgSnapshot& snap, uint64_t address);
    bool prepareInstructionPatchDraft(const std::vector<Instruction>& instructions, Arch arch);
    bool applyStaticInstructionPatch(AppContext& ctx, uint64_t address,
                                      std::vector<uint8_t> bytes, uint32_t span, bool padNop,
                                      const ListingInstructionSnapshot* retainedOriginal = nullptr,
                                      PatchApplyOutcome* outcome = nullptr);
    std::unordered_set<uint64_t> listingLocTargets_; // persistent direct/xref targets
    uint64_t             listingLocKey_ = ~0ull;     // image/arch/engine identity
    bool                 listingWeightsChanged_ = false;
    bool                 listingAnchorPending_ = false;
    uint64_t             listingAnchorVA_ = 0;
    // Last real top-of-viewport address. Same-image cache/index rebuilds and
    // asynchronous prefix reconciliation restore this instead of allowing an
    // estimated-row change to throw the user into a neighbouring page.
    bool                 listingViewportAnchorValid_ = false;
    uint64_t             listingViewportAnchorVA_ = 0;
    static constexpr size_t kCodePageCacheCap = 96;
    static constexpr size_t kCodePagePrefixSyncPages = 1;
    uint64_t estimatedCodePageRows(const ListRow& page, Arch arch) const;
    uint64_t listingLocationKey(AppContext& ctx) const;
    uint64_t listingCodePageKey(AppContext& ctx) const;
    void invalidateMaterializedListingPage(AppContext& ctx, size_t descriptorIndex);
    void invalidatePatchedListingSpan(AppContext& ctx, uint64_t address, size_t byteCount,
                                      bool invalidateAuthority = true);
    void resetListingVirtualIndex(AppContext& ctx, bool clearLocations = false);
    void invalidateListingPageRows(uint64_t address); // rename changes a materialized loc_ row only
    bool resolveListingCodePagePrefix(AppContext& ctx, size_t descriptorIndex);
    bool listingInstructionBoundaryExact(uint64_t address) const;
    bool listingInstructionBoundaryActionable(uint64_t address) const;
    bool listingDisplayedInstructionStart(uint64_t address) const;
    bool acceptListingInstructionBoundary(AppContext& ctx, uint64_t address);
    CodePageCache* ensureListingCodePage(AppContext& ctx, size_t descriptorIndex);
    bool findListingInstructionOwner(AppContext& ctx, size_t descriptorIndex,
                                     uint64_t address, size_t& ownerOut,
                                     int& instructionOut);
    bool locateListingAddress(AppContext& ctx, uint64_t address, uint64_t& virtualRow,
                              bool instructionOnly = false);
    void absorbListingTargets(AppContext& ctx, const XrefIndex& index);
    bool                 asmFullProgram_ = true;
    ListingLayout        listingLayout_;
    std::shared_ptr<const CodeDataMap> codeDataMap_; // worker-built global executable partition
    uint64_t             listingLayoutRevision_ = 1;
    bool                 listingLayoutDirty_ = false; // mirror into ProjectState this frame

    // Windowed assembly has a separate small cache; the full listing is backed by
    // the bounded page LRU above rather than an address-per-instruction cache.
    // Windowed assembly decodes up to 256 instructions. Cache that whole window
    // while the cursor/image/function bounds are unchanged instead of repeating
    // alignment, allocation, decode, and function-set construction every frame.
    uint64_t                                  asmWindowKey_ = ~0ull;
    uint64_t                                  asmWindowCursor_ = ~0ull;
    bool                                      asmWindowBoundaryExact_ = false;
    std::vector<Instruction>                  asmWindowInsns_;
    std::unordered_set<uint64_t>              asmWindowFuncSet_;
    // The bounded static view refills around this independent browse focus when
    // the user wheels through either edge; selection/cursor state stays intact.
    bool                                      asmWindowBrowseValid_ = false;
    uint64_t                                  asmWindowBrowseVA_ = 0;
    // Pending bounded-window refill: -1 earlier, +1 later, 0 none. Keeping the
    // direction pending until the rebuilt extent is checked prevents an equal
    // window or transient read failure from becoming a permanent edge lock.
    int8_t                                    asmWindowRefillDirection_ = 0;
    bool                                      asmWindowPanScrollValid_ = false;
    uint64_t                                  asmWindowPanScrollVA_ = 0;
    bool                                      asmWindowScrollSampleValid_ = false;
    float                                     asmWindowLastScrollY_ = 0.0f;
    bool                 functionsDirty_ = false;   // a patch changed code: re-run analyzeFunctions before the next decompile/CFG
    PatchRefreshDebouncer patchRefresh_;            // keeps current rows visible while edit bursts settle
    uint64_t             analysisIsaSig_ = ~0ull;  // selected arch + effective decoder used by derived caches
    void invalidateArchitectureAnalysis(AppContext& ctx);

    // Static-listing branch arrows: per-frame geometry collected inside renderAsmRow
    // (one record per visible instruction row), drawn after EndTable. Mutually
    // exclusive views (full vs windowed) reuse this single sink; it is cleared at
    // the top of whichever view renders this frame. Reuses showJumpArrows_ as the toggle.
    struct AsmFlowRow { uint64_t addr; uint64_t target; bool branch; float y; };
    std::vector<AsmFlowRow> asmFlow_;
    float                   asmLaneX_ = 0.0f, asmAddrX_ = 0.0f;
    bool                    asmGotLaneX_ = false, asmGotAddrX_ = false;

    // Row "glow" highlights: per-frame geometry collected during row rendering
    // (static + live listings share the sink) and painted over the table after
    // EndTable — same late-draw approach as the branch arrows, since an in-row
    // window-drawlist rect would clip to the current CELL, not the row. Distinct
    // theme-routed colors per cause: RIP (good/green), cursor = what the user
    // clicked (accent), the cursor instruction's branch target (jump/violet),
    // plus a decaying white-hot navigation-arrival flash on top.
    struct RowGlow { float y; float h; unsigned int colorPacked; float intensity; };
    std::vector<RowGlow> rowGlow_;
    void  drawRowGlows(float x0, float y0, float x1, float y1,
                       ImDrawList* listingDrawList = nullptr); // paint + clear rowGlow_
    void  pushRowGlow(float yCenter, bool rowAtRip, bool rowSel, bool rowJump,
                      bool rowTraced, float flash);
    float navFlashAt(uint64_t addr);   // 1..0 decaying flash if addr was just navigated to
    uint64_t hlJumpVA_   = 0;          // branch target of the cursor's instruction (per frame)
    bool     hlJumpValid_ = false;     // target VA 0 is representable
    uint64_t navFlashVA_ = 0;          // navigation arrival flash target (VA 0 allowed)
    bool     navFlashValid_ = false;
    bool     navFlashLive_ = false;     // runtime flashes retire with their debugger identity
    double   navFlashT0_ = 0.0;        // ImGui::GetTime() when the flash started
    bool     followLiveRip_ = true;
    char     gotoBuf_[32] = "";
    char     byteSearch_[128] = "";
    std::vector<uint64_t> searchHits_;
    bool     byteSearchLive_ = false;  // search debuggee memory instead of the file
    // Search results retain the target identity captured when Find was pressed.
    // The editable query/mode and a reused PID are not sufficient ownership
    // proofs for data exported to the investigation worker.
    std::string byteSearchResultQuery_;
    uint64_t byteSearchImageRevision_ = 0;
    uint64_t byteSearchImageSerial_ = 0;
    uint64_t byteSearchSessionGeneration_ = 0;
    uint32_t byteSearchPid_ = 0;
    uint64_t byteSearchLiveToken_ = 0;
    uint64_t byteSearchLiveEpoch_ = 0;
    std::string byteSearchStatus_;
    std::string byteSearchMapWarning_;

    // Unified investigation workspace. Collection is a bounded, version-checked
    // state machine because functions/strings/xrefs are owned by this tab and may
    // contain hundreds of thousands of records. The resulting shared snapshot is
    // immutable and handed to Core/InvestigationService for build + query work.
    enum class InvestigationCollectPhase : uint8_t {
        Functions,
        Strings,
        Imports,
        Comments,
        Resources,
        ByteResults,
        TextResults,
        Xrefs,
        NetworkTrail,
        Authorization,
        LiveModules,
        RecentQueries,
        Complete,
    };
    std::shared_ptr<InvestigationSnapshot> investigationCollecting_;
    std::shared_ptr<const InvestigationSnapshot> investigationPublished_;
    InvestigationCollectPhase investigationCollectPhase_ = InvestigationCollectPhase::Complete;
    size_t investigationCollectIndex_ = 0;
    size_t investigationXrefSourceIndex_ = 0;
    size_t investigationAuthorizationStageIndex_ = 0;
    decltype(XrefIndex::toTarget)::const_iterator investigationXrefIt_{};
    std::unordered_map<uint64_t, std::string>::const_iterator investigationCommentIt_{};
    uint64_t investigationCollectSignature_ = 0;
    uint64_t investigationPublishedSignature_ = ~uint64_t{0};
    uint64_t investigationPublishedGeneration_ = 0;
    uint64_t investigationImageSerial_ = 1;
    uint64_t investigationXrefSerial_ = 1;
    uint64_t investigationByteResultsSerial_ = 1;
    uint64_t investigationTextResultsSerial_ = 1;
    bool investigationBuilding_ = false;

    // Exact static owner/image identity. DocumentId prevents a retained child
    // from ever rendering against another document; imageGeneration detects
    // replacement even when BinaryFile revision/path/hash values collide.
    DocumentId documentId_{};
    uint64_t observedImageGeneration_ = 0;
    bool observedImageGenerationValid_ = false;

    // ---- Live disassembly view state ----
    int       liveMode_       = 0;     // 0 = disassembly, 1 = pseudocode
    bool      showRegBox_     = false; // optional extra live register pane; lower Registers is always reachable
    bool      showJumpArrows_ = true;  // branch arrows drawn in the flow gutter
    bool      showRegHints_   = true;  // inline "rax=0x..." hints on the RIP row
    Registers regsAtLastStop_{};       // registers captured at the current stop
    Registers regsAtPrevStop_{};       // ...and the one before, for change tinting
    // Inline editing in the Registers tab (only while Paused). Hex edits write
    // the raw value; text edits allocate a target C string and write its pointer.
    int       regEditIdx_   = -1;      // index into the register table being edited
    std::vector<char> regEditBuf_ =
        std::vector<char>(kRegisterEditMaxInputBytes + 1, '\0');
    bool      regEditFocus_ = false;
    bool      focusRegistersTab_ = false; // compact register-box edit handoff
    bool      focusBreakpointsTab_ = false;
    bool      listingHeaderRendered_ = false;
    DebugTargetIdentity regEditOwner_{};
    uint32_t regEditTid_ = 0;
    uint64_t regEditRip_ = 0;
    bool regEditIs32_ = false;
    std::string regEditStatus_;
    bool regEditStatusError_ = false;
    uint64_t  stackEditAddr_ = 0;      // stack qword address being edited (0 = none)
    char      stackEditBuf_[20] = "";
    bool      stackEditFocus_ = false;
    uint64_t  lastStopRip_    = 0;
    bool      haveTwoStops_   = false;
    // describePointer() memo: register/stack pointer descriptions for the current stop.
    // Keyed by value; the whole map is dropped when the stop identity (ptrDescCacheKey_)
    // changes (see describePointer), so reads/symbol lookups run once per stop not per frame.
    std::unordered_map<uint64_t, std::string> ptrDescCache_;
    uint64_t  ptrDescCacheKey_ = 0;
    // Live listing inline string-comment memo: referenced VA -> formatted "; \"..\"".
    // Same per-stop invalidation as ptrDescCache_ (liveStopKey); without it the live
    // listing does 1-2 debuggee readMemory()s per data-referencing row, for all ~256
    // rows, every frame while paused.
    std::unordered_map<uint64_t, std::string> strCmtCache_;
    uint64_t  strCmtCacheKey_ = 0;
    struct MemoryValueSample {
        uint8_t bytes[8]{};
        size_t count = 0;
        double sampledAt = -1;
    };
    std::map<std::pair<uint64_t, uint16_t>, MemoryValueSample> memoryValueCache_;
    DebugTargetIdentity memoryValueOwner_{};
    uint64_t memoryValueStopKey_ = 0;
    int memoryValueFrame_ = -1;
    unsigned memoryValueReads_ = 0;
    uint64_t  lastScrolledRip_ = 0;    // focus addr we last auto-scrolled to (live view)
    bool      lastScrolledRipValid_ = false; // focus may legitimately be LIVE VA 0
    uint64_t  lastAsmScroll_   = 0;    // last centered static VA
    bool      lastAsmScrollValid_ = false;
    // Bound in synchronizeDocumentImage; this child cannot outlive its owner.
    DocumentNavigation* navigation_ = nullptr;
    bool restoringNavigation_ = false;
    uint64_t retainedLiveCursorVA_ = 0;
    bool retainedLiveCursorValid_ = false;
    uint64_t navigationLiveModuleSignature_ = 0;

    // Live listing decode cache: re-disassembling the on-screen window every frame
    // churned the heap (the working set climbed while attached). The decode + index
    // + function-divider set are rebuilt only when the signature below changes.
    std::vector<uint8_t>              liveBuf_;         // reused read scratch (never realloc'd per frame)
    std::vector<Instruction>         liveInsns_;        // cached decode of the current window
    std::unordered_map<uint64_t,int> liveIdxOf_;        // address -> index within liveInsns_
    std::unordered_set<uint64_t>     liveFuncSet_;      // divider addresses (runtime VAs)
    std::vector<uint64_t>            liveDecodeBoundaries_; // committed in-window boundaries, retained on refresh
    uint64_t                         liveCacheStart_ = 0;
    uint64_t                         liveCacheFocusVA_ = 0;
    uint64_t                         liveCacheSig_   = ~0ull;
    uint32_t                         liveGen_        = 0;  // bumped on live write / patch / re-analyze / detach
    // Manual edge scrolling gets a refill focus separate from cursor/RIP. This
    // allows continuous backward/forward browsing without polluting nav history.
    bool                             liveBrowseValid_ = false;
    uint64_t                         liveBrowseVA_ = 0;
    int8_t                           liveBrowseRefillDirection_ = 0;
    bool                             liveWindowPanScrollValid_ = false;
    uint8_t                          liveWindowScrollSettleFrames_ = 0; // shared focus/pan correction budget
    uint64_t                         liveWindowPanScrollVA_ = 0;
    float                            liveWindowPanScrollOffsetY_ = 0.0f;
    bool                             liveWindowScrollSampleValid_ = false;
    float                            liveWindowLastScrollY_ = 0.0f;
    bool                             wasAttached_    = false; // detach-edge detector (clear caches once)
    uint64_t                         liveSessionGenerationSeen_ = 0;
    uint32_t                         liveSessionPidSeen_ = 0;
    bool                             liveSessionIdentityValid_ = false;
    bool                             runtimeBannerDismissed_ = false; // runtime-wrapper/archive banner [x], reset per load

    // Decoder for the LIVE view, selected to match the DEBUGGEE's bitness. The static
    // ctx.staticDisassembler() follows the loaded file's arch, which can differ from the attached
    // process (e.g. a 32-bit WOW64 target debugged while an x64 file — or no file — is
    // loaded). Rebuilt only when the bitness changes; falls back to ctx.staticDisassembler().
    std::unique_ptr<IDisassembler>   liveDisasm_;
    int                              liveDisasmArch_   = -1; // Arch of liveDisasm_, -1 = none built
    int                              liveDisasmEngine_ = -1; // Engine of liveDisasm_ (a UI engine switch rebuilds it)
    IDisassembler*                   liveDecoder(AppContext& ctx, bool is32);

    // Live process search (strings / hex / values in committed memory).
    char                  liveFind_[128] = "";
    int                   liveFindKind_  = 0;   // 0=ASCII 1=UTF-16 2=hex 3=u64
    std::vector<uint64_t> liveFindHits_;
    std::string           liveFindStatus_;
    std::string           liveFindMapWarning_;
    DebugTargetIdentity   liveFindOwner_{};
    uint64_t              liveFindPatternToken_ = 0;
    uint64_t              liveFindPatternEpoch_ = 0;
    bool                  openFindPopup_ = false;

    // Live patching (write bytes straight into the debuggee).
    int                   patchMode_ = 1;       // 0 = hex bytes, 1 = assembly (Keystone)
    uint64_t              patchVA_  = 0;
    uint32_t              patchLen_ = 0;
    std::string           patchHex_;
    std::string           patchAsmText_;
    std::string           patchAsm_;            // disasm preview of edited bytes
    std::string           patchStatus_;
    std::string           runErr_;               // last "> Run" launch error, shown in the asm toolbar
    bool                  openPatchPopup_ = false;
    bool                  closePatchPopup_ = false; // debugger identity changed under an open live draft
    bool                  patchPopupLive_ = false;
    std::vector<ListingInstructionSnapshot> patchInstructionRecords_;
    std::vector<uint8_t> patchLiveOriginal_;
    std::vector<uint8_t> patchPreviewOriginal_;
    PatchApplyOutcome patchPopupOutcome_{};
    uint32_t              patchPopupPid_ = 0;
    uint64_t              patchPopupSessionGeneration_ = 0;
    bool                  patchPadNop_ = true;   // NOP-pad a short encoding up to the original length
    // Destination for newly-created patch records. A disabled destination is
    // intentionally selectable so mutually-exclusive alternatives can be
    // authored without changing the current static/live experiment.
    uint64_t              patchDestinationSetId_ = 0;
    uint64_t              patchManageSetId_ = 0; // zero means no named row selected
    uint64_t              patchReassignSetId_ = 0;
    char                  patchNewSetName_[129] = "";
    char                  patchRenameSetName_[129] = "";
    std::string           patchSetDiagnostic_;
    int                   patchCompareLeft_ = 0;  // 0=current, 1=baseline, 2=Ungrouped, 3+=named set
    int                   patchCompareRight_ = 1;
    PatchSetComparisonResult patchCompareResult_;
    bool                  patchCompareValid_ = false;
    uint64_t              patchCompareSignature_ = 0;
    bool                  patchRevertSetConfirm_ = false;
    uint64_t              patchRevertSetId_ = 0;
    LivePatchOriginalMap  livePatchOriginals_;  // FILE VA -> exact-session runtime original
    std::unordered_map<uint64_t, uint64_t> livePatchSetOwners_; // FILE VA -> set id whose live write retained the original
    size_t                livePatchOriginalBytes_ = 0;
    int                   hwSizeSel_   = 1;      // data-breakpoint length (1/2/4/8) chosen in the HW submenu

    // Functions / modules browser (lower "Functions" sub-tab).
    std::vector<ModuleInfo> liveModules_;
    uint32_t                liveModulesPid_ = 0;
    uint64_t                liveMainBase_    = 0;   // cached runtime base of the main module
    uint32_t                liveMainBasePid_ = 0;   // pid the cache was computed for
    char                    funcTabFilter_[128] = "";
    std::vector<int>        funcTabVisible_;          // cached lower Functions-tab filter result
    char                    funcTabFilterLast_[128] = "\x01";
    uint64_t                funcTabVisSig_ = ~0ull;
    uint32_t                funcTabVisNamesGen_ = 0;

    // Pseudocode cache (regenerated when the function or RIP context changes).
    uint64_t              pseudoVA_ = 0;
    std::string           pseudoText_;
    std::vector<std::string> pseudoLines_;
    std::vector<SourceOrigin> pseudoOrigins_;

    // Decompiler (structured pseudo-C) for the static Pseudocode view. The decompile
    // runs off the render thread (K_Decompile); decompVA_ is the function currently
    // shown when decompValid_ is true (VA 0 is valid), decompText_ its result, and
    // decompPending_ true while the worker is running.
    // decompLines_/decompLineOrigins_ are decompText_ split per line plus the
    // validity-bearing source origins backing click-to-navigate (including VA 0).
    // decompLru_ keeps the few most-recently decompiled functions so nav back/forward
    // is instant (no re-decompile); a small linear list (front = most recent), capped.
    uint64_t              decompVA_ = 0;
    bool                  decompValid_ = false;
    std::string           decompText_;
    std::vector<std::string> decompLines_;
    std::vector<uint64_t>    decompLineVA_;
    std::vector<SourceOrigin> decompLineOrigins_;
    bool                     decompComplete_ = true;
    std::string              decompIncompleteReason_;
    std::vector<DecompileDiagnostic> decompDiagnostics_;
    bool                  decompPending_ = false;
    bool                  decompOwnershipPending_ = false;
    bool                  decompOwnershipValid_ = false;
    // An address that is not owned by an analyzed function is never silently
    // treated as a function. The user may explicitly authorize one bounded
    // fallback request; moving the cursor retires that authorization.
    uint64_t              decompBoundedRangeVA_ = 0;
    bool                  decompBoundedRangeValid_ = false;
    static constexpr size_t kDecompLruCap = 16;
    struct DecompCacheEntry {
        uint64_t va = 0;
        uint64_t context = 0;
        DecompResult result;
    };
    std::list<DecompCacheEntry> decompLru_;
    uint64_t            decompContextGeneration_ = 1;
    void                retireStaticDecompilation();
    void                retireUnavailableDecompOwnership();
    uint64_t            decompScopeContext(bool boundedRange) const;
    const DecompResult* decompLruGet(uint64_t va, uint64_t context); // recently-decompiled cache lookup (nav back/fwd)
    void                decompLruPut(uint64_t va, uint64_t context, const DecompResult& r);
    std::shared_ptr<const DecompileNameMap> decompNamesSnapshot_; // reused across function navigation
    std::shared_ptr<const std::vector<uint64_t>> decompNoreturnSnapshot_;
    uint64_t              decompNamesFunctionsGen_ = ~0ull;
    uint32_t              decompNamesNamesGen_ = ~0u;
    void setDecompContent(std::string text, std::vector<uint64_t> lineVA,
                          std::vector<SourceOrigin> origins = {},
                          bool complete = true, std::string incompleteReason = {},
                          std::vector<DecompileDiagnostic> diagnostics = {});
    // Pseudocode output language (0 = pseudo-C, 1 = Python). The worker/LRU always
    // hold pseudo-C; applyDecompLang translates on display (DecompileToPython is a
    // pure text transform), so switching languages never re-decompiles.
    int  pseudoLang_ = 0;
    void applyDecompLang(const DecompResult& c);

    // ---- Hex editor (main view 2) ----
    // Whole-file clipper-rendered hex view addressed by FILE OFFSET (uniform rows;
    // VA gaps don't fragment the view), with per-row VA via offsetToVA. Edits go
    // through applyPatchBytes (one PjPatch per byte) so they revert/save like any
    // other patch. hexCursorOff_ is the canonical hex cursor; cursorVA_ syncs both
    // ways (external navigation scrolls the hex view; clicking a mapped byte moves
    // the global cursor).
    uint64_t hexCursorOff_   = 0;
    uint64_t hexLastScroll_  = 0;       // last cursorVA_ synchronized into Hex
    bool     hexLastScrollValid_ = false;
    uint64_t hexPendScroll_  = ~0ull;   // pending scroll-to file offset (~0 = none)
    int      hexEditNibble_  = -1;      // -1 idle; 0 = high nibble typed (in hexEditByte_)
    uint8_t  hexEditByte_    = 0;
    bool     hexAsciiCol_    = false;   // typing targets the ascii column
    bool     hexDragging_    = false;   // mouse selection drag in progress
    uint64_t hexSelA_ = ~0ull, hexSelB_ = ~0ull;   // selection anchor/end (file offsets, inclusive)
    char     hexGotoOff_[20] = "";
    std::vector<std::pair<uint64_t, uint64_t>> hexPatchedIv_;  // sorted [offLo,offHi) patched spans
    uint64_t hexPatchedSig_  = ~0ull;

    // User annotations (persist via ctx.staticProject()). comments_ render in the
    // listing; names_ override symbol resolution everywhere names appear.
    std::unordered_map<uint64_t, std::string> comments_;
    std::unordered_map<uint64_t, std::string> names_;
    // Resolved PE imports: IAT slot VA -> "dll.func" (built on load from the
    // BinaryFile import table), so call/jmp through the IAT shows the API name.
    std::unordered_map<uint64_t, std::string> importMap_;
    char                  importFilter_[64] = "";
    char                  importFilterLast_[64] = "\x01";
    uint64_t              importVisSig_ = ~0ull;
    char                  exportFilter_[96] = "";
    char                  exportFilterLast_[96] = "\x01";
    std::vector<int>      exportVisible_;
    uint64_t              exportVisSig_ = ~0ull;
    size_t                exportCodeCount_ = 0;
    size_t                exportForwardCount_ = 0;
    size_t                exportDataCount_ = 0;
    size_t                exportUnmappedCount_ = 0;
    // Resources tab (PE resource directory): selection + cached preview of the
    // selected leaf. The preview cache is keyed by (index, image revision) so a
    // patch or reload rebuilds it.
    char                  resourceFilter_[96] = "";
    int                   resourceSel_        = -1;    // selected leaf index into ctx.staticBinary().resources()
    int                   resourcePreviewFor_ = -2;    // resourceSel_ the cache was built for
    uint64_t              resourcePreviewSig_ = ~0ull; // imageRevision the cache was built for
    bool                  resourcePreviewText_ = false;// preview body is decoded text (else hex dump)
    std::string           resourcePreviewMeta_;        // one-line metadata header
    std::string           resourcePreviewBody_;        // decoded text (version / manifest / string table)
    std::vector<uint8_t>  resourceSaveBytes_;          // reconstructed .bmp/.ico (empty => raw-only save)
    std::string           resourceSaveName_;           // suggested filename for the reconstructed save
    std::string           resourceSaveLabel_;          // e.g. "Save as .bmp" ("" => no reconstruction)
    // Comment / rename / breakpoint-condition edit popups.
    uint64_t              annPopupVA_ = 0;
    char                  commentBuf_[512] = "";
    char                  renameBuf_[128]  = "";
    char                  condPopupBuf_[160] = "";
    std::string           condPopupError_;            // validation failure; popup stays open
    bool                  openCommentPopup_ = false;
    bool                  openRenamePopup_  = false;
    bool                  openCondPopup_    = false;
    bool                  closeCondPopup_   = false; // debugger identity changed under an open live draft
    bool                  condPopupLive_ = false;
    uint32_t              condPopupPid_ = 0;
    uint64_t              condPopupSessionGeneration_ = 0;
    bool                  openAnalystOverridePopup_ = false;
    uint64_t              analystOverrideVA_ = 0;
    int                   analystFunctionAction_ = 0; // 0 unchanged, 1 define, 2 undefine
    bool                  analystExtentEnabled_ = false;
    char                  analystExtentBuf_[32] = "";
    int                   analystNoreturn_ = 0; // 0 unspecified, 1 false, 2 true
    char                  analystConventionBuf_[65] = "";
    char                  analystPrototypeBuf_[4097] = "";
    int                   analystMode_ = 0; // unspecified/ARM/Thumb
    bool                  analystDataEnabled_ = false;
    int                   analystDataKind_ = 1; // PjDataKind ordinal
    char                  analystDataSizeBuf_[32] = "";
    char                  analystDataTypeBuf_[4097] = "";
    std::string           analystOverrideError_; // invalid draft stays in the modal
    bool                  projectLoaded_    = false;  // loadProjectState ran for this image
    bool                  projectDirty_     = false;  // an annotation changed: mirror to ctx.staticProject() this frame
    std::string           projectPatchWarning_;      // malformed/unmapped saved patches were not applied

    // Inline string/data comments + cross-reference (xref) search.
    bool                  showStringComments_ = true;
    bool                  showMemoryValues_   = true;
    bool                  showHints_          = true;   // inline "what it does" gloss per instruction
    bool                  gmlReadableInstructions_ = true; // display labels; decoded bytecode stays exact
    uint64_t              xrefTarget_ = 0;
    bool                  xrefTargetValid_ = false;
    bool                  xrefPinned_ = false;
    bool                  xrefTargetsList_ = false;
    DebugTargetIdentity   xrefLiveOwner_{};
    uint64_t              xrefLiveModules_ = 0;
    uint64_t              xrefResultsVersion_ = 0;
    uint64_t              xrefFilterVersion_ = ~0ull;
    uint32_t              xrefFilterNames_ = ~0u;
    uint64_t              xrefFilterFunctions_ = ~uint64_t{0};
    size_t                xrefFilterCursor_ = 0;
    char                  xrefFilter_[192] = "";
    std::string           xrefAppliedFilter_;
    std::vector<size_t>   xrefVisible_;
    uint64_t              xrefSelectedSource_ = 0;
    bool                  xrefSelectedValid_ = false;
    std::vector<uint64_t> xrefHits_;
    std::shared_ptr<const std::vector<uint64_t>> xrefFileHits_;
    const std::vector<uint64_t>& pinnedXrefSources() const;
    void advancePinnedXrefFilter(AppContext& ctx, size_t budget = 512);
    bool                  xrefHitsLive_ = false;   // hits are runtime VAs (searched the debuggee)
    std::string           xrefStatus_;
    bool                  openXrefPopup_ = false; // retained name: requests focus of the nonmodal Xrefs panel
    // Attached xref search runs off the render thread on LiveScanService; this token
    // matches the in-flight request so a stale/older sweep's result is ignored.
    bool                  xrefScanning_ = false;
    uint64_t              xrefToken_    = 0;
    bool                  xrefFileOwned_ = false;
    bool                  xrefFilePending_ = false;
    uint64_t              xrefFileImageSerial_ = 0;
    uint64_t              xrefFileImageRevision_ = 0;
    uint64_t              xrefFileEpoch_ = 0;
    uint64_t              xrefFileIsaSig_ = 0;
    uint64_t              xrefFileScope_ = 0;
    bool                  xrefFileScopeValid_ = false;
    // Whole-program xref index (sources per target), built lazily from the on-disk
    // image and cached by the listing content signature; powers the "Xrefs" tab.
    XrefIndex             xrefIndex_;
    uint64_t              xrefIndexSig_ = ~0ull;
    uint64_t              xrefRequestedSig_ = ~0ull;   // last sig we asked the worker to index (dedup re-requests)
    // Retain the cursor/enclosing-function groups across frames. Clipping rows
    // alone does not bound repeated grouping or counting of a high-fan-out index.
    struct XrefPanelGroups {
        bool valid = false;
        uint64_t target = 0;
        std::vector<uint64_t> writers, readers, takers, branches;
    };
    XrefPanelGroups       xrefPanelGroups_[2];
    bool                  xrefPanelCacheValid_ = false;
    uint64_t              xrefPanelImageSerial_ = 0;
    uint64_t              xrefPanelResultSerial_ = 0;
    uint64_t              xrefPanelIndexSig_ = 0;
    size_t                xrefPanelEdgeCount_ = 0;
    // Analysis export (File > Export Analysis) result, shown in a small popup.
    std::string           exportStatus_;
    bool                  openExportPopup_ = false;
    // Save ASM / Save C workflow. `codeExportHasFunction_` makes VA zero a valid
    // current-function target; the Core service owns all heavy work/file I/O.
    CodeExportFormat      codeExportFormat_ = CodeExportFormat::Assembly;
    CodeExportScope       codeExportScope_  = CodeExportScope::WholeProgram;
    CodeExportCStyle      codeExportCStyle_ = CodeExportCStyle::Readable;
    uint64_t              codeExportFunctionVA_ = 0;
    bool                  codeExportHasFunction_ = false;
    bool                  openCodeExportPopup_ = false;
    bool                  codeExportStarted_ = false;
    std::string           codeExportStatus_;

    // Symbol / function-name resolution.
    bool                  showNames_ = true;   // resolve call/jmp targets to names
    bool                  symAttached_ = false;// cached once per frame (avoid re-locking debug snapshot)
    uint32_t              symPid_ = 0;
    const DbgSnapshot*    frameSnap_ = nullptr; // borrowed App render snapshot (or fallback below)
    DbgSnapshot           fallbackFrameSnap_;  // standalone/test render fallback
    uint64_t              frameStaticRip_ = 0; // exact LIVE->FILE projection for static-row highlighting
    bool                  frameStaticRipValid_ = false;
    // Parsed export tables for live modules: base -> sorted (va, name).
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, std::string>>> modExports_;
    SymbolService                               symbols_;     // sole background DbgHelp/PDB owner
    std::unordered_map<uint64_t, std::string>   symCacheFile_; // FILE addr -> resolved name
    std::unordered_map<uint64_t, std::string>   symCacheLive_; // LIVE addr -> resolved name
    uint64_t                                    symbolOptionsSeen_ = 0;
    bool                                        symbolContextValid_ = false;
    bool                                        symbolContextLive_ = false;
    uint32_t                                    symbolContextPid_ = 0;
    uint64_t                                    symbolContextSessionGeneration_ = 0;
    uint64_t                                    symbolContextModuleSig_ = 0;
    std::string                                 symbolContextPath_;
    uint64_t                                    symbolContextImageBase_ = 0;

    // Call stack (real DbgHelp StackWalk64 unwind from the debugger when available,
    // else a heuristic RSP/RBP scan). Recomputed per stop.
    std::vector<CallFrame> callStack_;
    bool                   callStackReal_ = false;   // true = real unwind, false = heuristic
    BacktraceStop          callStackStop_;
    bool                   callStackCacheValid_ = false;
    bool                   callStackScanRequested_ = false;
    bool                   callStackScanLimited_ = false;
    bool                   focusCallStackTab_ = false;
    size_t                 callStackSelected_ = 0;
    std::string            callStackStatus_;
    int                    stackRows_ = 24;   // qwords shown in the live Stack tab

    // Goto-by-name: symbol index (addr, "module.name") + the picker popup. `lower`
    // is a pre-lowercased copy of `name`, built once, so filtering doesn't re-lower
    // every (up to 120k) entry on each keystroke. (SymEntry is declared in the
    // public section so the command palette can consume the index.)
    std::vector<SymEntry>                         symbolIndex_;
    uint64_t                                      symbolIndexSig_ = ~0ull;
    uint64_t                                      symbolLiveModulesSig_ = ~0ull;
    bool                                          openGotoPopup_ = false;
    char                                          gotoNameBuf_[96] = "";
    std::vector<int>                              gotoMatches_;   // indices into symbolIndex_
    std::string                                   gotoFilterLast_;
    bool submitGoto(AppContext& ctx, const char* query, bool popup);
    bool resolveGotoAddress(AppContext& ctx, uint64_t address, bool live, bool popup);
    void pollPendingGoto(AppContext& ctx);
    std::string gotoStatus_;
    struct PendingGoto {
        bool active = false;
        bool popup = false;
        bool live = false;
        std::string query;
        uint64_t imageGeneration = 0;
        uint64_t imageRevision = 0;
        DecoderConfig decoder;
        DebugTargetIdentity target{};
        uint64_t moduleSignature = 0;
        DocumentLocation origin;
    } pendingGoto_;

    // Disassembly text search (mnemonic / operands).
    char                  textSearch_[128] = "";
    bool                  textCaseSensitive_ = false;
    std::vector<uint64_t> textHits_;
    bool                  textHitsLive_ = false;   // hits are runtime VAs (searched the debuggee)
    std::string           textStatus_;
    bool                  openTextPopup_ = false;
    struct TextSearchSpan { uint64_t base = 0, size = 0; };
    std::vector<TextSearchSpan> textSearchSpans_;
    size_t                textSearchSpan_ = 0;
    uint64_t              textSearchOffset_ = 0;
    uint64_t              textSearchDone_ = 0;
    uint64_t              textSearchTotal_ = 0;
    uint64_t              textSearchUnreadable_ = 0;
    uint64_t              textSearchImageRevision_ = 0;
    uint64_t              textSearchImageSerial_ = 0;
    uint64_t              textSearchIsaSig_ = 0;
    uint64_t              textSearchSessionGeneration_ = 0;
    uint32_t              textSearchPid_ = 0;
    bool                  textSearchActive_ = false;
    bool                  textSearchCi_ = true;
    std::string           textSearchNeedle_;
    std::vector<uint8_t>  textSearchLiveBuffer_;

    // Highlight-on-hover: the token under the mouse last frame (live + static disasm).
    std::string           hoverToken_;

    // CFG graph: per-block manual drag offsets (block start VA -> dx, dy).
    std::unordered_map<uint64_t, std::pair<float, float>> cfgDrag_;
    ui::GraphViewport     cfgView_;
    bool                  cfgViewNeedsCenter_ = true;
    uint64_t              cfgViewCursor_ = 0;
    bool                  cfgViewCursorValid_ = false;
    int                   cfgDragBlock_ = -1;
    bool                  cfgPanActive_ = false;
    // Cached CFG for the graph view. BuildCFG decodes up to 1500 instructions and runs
    // dominator/loop analysis, so rebuild only when the root VA, decoder, or code-window
    // bytes change (see renderGraph) rather than every frame.
    ControlFlowGraph      cfgCache_;
    uint64_t              cfgCacheSig_ = ~0ull;

    // Trace coverage is session-only debugger state. Basic-block candidates are
    // derived incrementally from lazy CodePages, then grouped by owning page and
    // proven against exact decoded instruction starts before any int3 is planted.
    // Both discovery and validation are sliced across rendered frames; the sorted
    // proven-site vectors also let the listing shade hit blocks without row scans.
    static constexpr size_t kTraceSiteCap = 65536;
    static constexpr size_t kTraceRowsPerFrame = 1024;
    static constexpr size_t kTraceCandidateCap = kTraceSiteCap * 4;
    static constexpr size_t kTraceValidationPagesPerFrame = 4;
    bool                     traceSeedPlanning_ = false;
    bool                     traceSeedValidating_ = false;
    DebugTargetIdentity      traceSeedTarget_{};
    size_t                   traceSeedRow_ = 0;   // current descriptor
    size_t                   traceSeedInsn_ = 0;  // instruction within decoded page
    size_t                   traceSeedCandidatePos_ = 0;
    size_t                   traceSeedFunctionPos_ = 0;
    size_t                   traceSeedSkippedPages_ = 0;
    size_t                   traceSeedInvalidRows_ = 0;
    bool                     tracePrevEndsBlock_ = true;
    bool                     traceSeedStreamExact_ = false;
    uint64_t                 tracePlanImageRevision_ = 0;
    uint64_t                 tracePlanListingSig_ = 0;
    uint64_t                 tracePlanTopology_ = 0;
    uint64_t                 tracePlanDecoder_ = 0;
    uint64_t                 tracePlanModuleBase_ = 0;
    uint64_t                 tracePlanModuleSize_ = 0;
    uint64_t                 tracePlanModuleGeneration_ = 0;
    std::vector<uint64_t>    traceSeedFile_;
    std::vector<TraceCodeSpan> traceSeedSpans_;
    std::unordered_set<uint64_t> traceSeedDedup_;
    std::vector<std::pair<size_t, uint64_t>> traceSeedCandidates_; // (CodePage descriptor, VA)
    std::unordered_set<uint64_t> traceCandidateDedup_;
    std::vector<uint64_t>    traceBlockStartsFile_;
    std::vector<uint64_t>    traceBlockStartsLive_;
    std::vector<TraceCodeSpan> traceBlockSpansFile_;
    std::vector<TraceCodeSpan> traceBlockSpansLive_;
    uint64_t                 traceBlockGeneration_ = 0;
    uint64_t                 traceBlockImageRevision_ = 0;
    uint64_t                 traceBlockDecoder_ = 0;
    DebugTargetIdentity      traceBlockTarget_{};
    uint64_t                 traceBlockModuleBase_ = 0;
    uint64_t                 traceBlockModuleGeneration_ = 0;
    std::unordered_map<uint64_t, uint64_t> traceInstructionHitsFile_;
    std::unordered_map<uint64_t, uint64_t> traceInstructionHitsLive_;
    std::unordered_map<uint64_t, uint64_t> traceBlockHitsFile_;
    std::unordered_map<uint64_t, uint64_t> traceBlockHitsLive_;
    uint64_t                 traceDisplayRevision_ = ~0ull;
    uint64_t                 traceDisplayImageKey_ = ~0ull;
    bool                     traceDisplaySuppressRefresh_ = false;

    // Call graph: cached call edges between discovered functions (fn -> callees,
    // and the reverse). Rebuilt when the function set changes.
    std::unordered_map<uint64_t, std::vector<uint64_t>> callees_;
    std::unordered_map<uint64_t, std::vector<uint64_t>> callers_;
    uint64_t              callGraphSig_ = ~0ull;
    uint64_t              callGraphRequestedSig_ = ~0ull;   // last sig asked of the worker (dedup re-requests)
    uint64_t              callGraphViewRoot_ = 0;
    bool                  callGraphViewRootValid_ = false;

    std::vector<Bookmark> bookmarks_;
    std::unordered_set<uint64_t> breakpoints_;   // O(1) membership in the hot render path
    std::unordered_set<uint64_t> disabledBreakpoints_; // retained FILE intent; not physical arming state
    // Saved FILE-space intent is separate from debugger acknowledgement. A
    // queued command is owned by one session and one module incarnation.
    struct StaticBreakpointArming {
        uint32_t pid = 0;
        uint64_t sessionGeneration = 0;
        uint64_t runtimeVA = 0;
        uint64_t moduleBase = 0;
        uint64_t moduleLoadGeneration = 0;
        bool queued = false;
        int queuedFrame = -1;
        std::string error;
    };
    std::unordered_map<uint64_t, StaticBreakpointArming> staticBreakpointArming_;
    std::unordered_map<uint64_t, std::string> staticBreakpointValidationErrors_;
    std::unordered_set<uint64_t> staticBreakpointSavedRestore_;
    std::unordered_set<uint64_t> staticBreakpointExplicitAdds_;
    uint64_t staticBreakpointRestoreImageRevision_ = 0;
    uint64_t staticBreakpointRestoreIsa_ = 0;
    std::vector<uint64_t> staticBreakpointSweep_;
    size_t staticBreakpointSweepPosition_ = 0;
    uint64_t staticBreakpointSweepSignature_ = 0;
    bool staticBreakpointSweepDirty_ = true;
    bool staticBreakpointRetryPending_ = false;
    double staticBreakpointRetryAt_ = 0.0;
    int staticBreakpointCheckFrame_ = -1;
    size_t staticBreakpointFrameChecks_ = 0;
    std::vector<Strng>    strings_;
    // Incremental K_Strings delivery can precede the matching K_Listing result.
    // Existing listing string rows still carry indices into the previous vector,
    // so retain that backing without copying until the replacement row topology
    // arrives. The side Strings panel continues to use strings_ immediately.
    std::vector<Strng>    retainedListingStrings_;
    bool                  listingUsesRetainedStrings_ = false;
    std::vector<Func>     functions_;
    // Sorted (address -> index into functions_) lookup, rebuilt lazily when the
    // function set changes. Lets symbolFor / status bar / live views find the
    // function containing an address by binary search instead of a linear scan.
    std::vector<std::pair<uint64_t,int>> funcIndex_;
    bool                                 funcIndexDirty_ = true;
    const Func* funcContaining(uint64_t addr);   // highest-start owned chunk containing addr, or nullptr
    std::unordered_map<uint64_t, std::string> condBuf_; // per-bp condition edit text
    // Invalid table edits remain available for correction but are never copied
    // into condBuf_ (the persisted/applied condition map).
    std::unordered_map<uint64_t, std::string> condEditDraft_;
    std::unordered_map<uint64_t, std::string> condEditError_;
    std::unordered_map<uint64_t, std::string> liveCondEditDraft_; // exact-session runtime VAs
    std::unordered_map<uint64_t, std::string> liveCondEditError_;
    std::unordered_map<uint64_t, uint32_t> everyNBuf_;  // per-bp "break every Nth hit" (0/1 = every)
    uint32_t breakpointActionsPopupId_ = 0;
    uint64_t breakpointActionsContext_ = 0;
    char                  fcCodeBuf_[16] = "";          // first-chance whitelist hex-code entry
    size_t                dbgOutSeen_ = 0;              // Debug Output auto-scroll watermark
    // Heuristic function naming: address -> the basis for the guessed name (tooltip).
    // Guesses live in Func::name (so they flow through symbolFor everywhere) but are
    // never persisted — they are recomputed from the image on each analyze.
    std::unordered_map<uint64_t, std::string> guessReason_;
    bool                  guessNames_ = true;    // run the name guesser after analysis
    std::string           fnSummary_;
    char                  fnFilter_[128] = "";
    char                  strFilter_[64] = "";
    int                   fnCategory_ = 0;
    int                   strEncoding_ = 0;
    // Filtered row indices for the side lists, clipper-rendered (these lists can hold
    // thousands of entries; rendering all of them was wasteful). Rebuilt ONLY when the
    // filter text or the underlying data changes — not every frame — since the rebuild
    // copies a std::string + probes the rename map per function (see fnVisSig_).
    std::vector<int>      fnVisible_;
    std::vector<int>      strVisible_;
    std::vector<int>      impVisible_;
    char                  fnFilterLast_[128] = "\x01";   // sentinel != "" forces a first build
    char                  strFilterLast_[64] = "\x01";
    uint64_t              fnVisSig_  = ~0ull;   // data signature of fnVisible_'s last build
    uint32_t              fnVisNamesGen_ = 0;
    void refreshFunctionFilter(bool lower);
    void renderFunctionDestinations(AppContext& ctx, uint64_t address);
    uint64_t              strVisSig_ = ~0ull;   // stringsGen_ of strVisible_'s last build
    uint32_t              namesGen_  = 0;       // bumped when user/guessed/discovered names change
    uint64_t              functionsGen_ = 0;    // bumped whenever functions_ membership/bounds change
    uint64_t              stringsGen_ = 0;      // bumped whenever strings_ is cleared/replaced
    bool                  stringsLive_ = false;    // scan debuggee memory instead of the file
    bool                  stringsScanned_ = false;
    bool                  stringsScanning_ = false; // an off-thread file/live scan is in flight
    bool                  stringsScanLive_ = false; // chooses the matching progress source
    bool                  stringsTruncated_ = false;// result cap omitted additional strings
    uint64_t              stringsToken_   = 0;      // matches the in-flight LiveScanService request
    uint32_t              stringsAutoPid_ = 0;     // exact debugger identity already auto-scanned
    uint64_t              stringsAutoSessionGeneration_ = 0;
    std::string           notes_;
    bool                  notesDirty_ = false;
    bool                  notesReloadEditor_ = false;

    // Algorithm recognition (AlgoScan / K_Intent): crypto/encoding matches from the
    // background recognizer, shown in the "Algorithms" lower sub-tab. algoLabels_ is the
    // user-confirmed evidence overlay, persisted via ctx.staticProject().algorithmLabels (matches
    // are recomputed each analyze; the label is the only persisted part).
    std::vector<AlgoMatch> algos_;
    bool                   algosScanned_ = false;
    int                    algoSel_ = -1;
    char                   algoFilter_[64] = "";
    std::unordered_map<uint64_t, std::string> algoLabels_;

    // Per-function annotation engine (Core/FuncAnnotate): heuristic calling
    // convention / args / frame / branch-meaning / loop / pattern notes, cached
    // in a tiny LRU keyed by function start. Only the cursor's function (and the
    // Annotations tab) builds eagerly; the per-row inline path returns cache
    // hits only (buildIfMissing=false), so fast scrolling never triggers CFG
    // builds. Invalidated when the listing signature changes.
    struct AnnEntry {
        uint64_t        fn = 0;
        FuncAnnotations ann;
        std::unordered_map<uint64_t, std::string> inlineText;   // va -> joined note text
        std::unordered_map<uint64_t, std::string> inlineTip;    // va -> kind/confidence/evidence tooltip
    };
    std::list<AnnEntry>     annLru_;            // front = most recent
    uint64_t                annSig_ = ~0ull;    // listingSig the cache was built for
    static constexpr size_t kAnnLruCap = 8;
    bool showFnNotes_ = true;                   // "Notes" toolbar toggle (inline annotations)
    int  annSel_ = -1;                          // Annotations tab: selected note row
    const AnnEntry* annotationsFor(AppContext& ctx, uint64_t va, bool buildIfMissing);
    void renderAnnotationsTab(AppContext& ctx);  // "Annotations" lower sub-tab

    // Java bytecode annotations (Core/JvmAnnotate): per-method stack effects /
    // depth / call-field-string extraction / category + check-method findings.
    // Same LRU discipline as annLru_ but for Arch::JVM methods, keyed by the
    // method's code offset. inlineEffect/inlineBranch index notes by bci for the
    // per-row inline path (cache-hit-only while scrolling).
    struct JvmAnnEntry {
        uint64_t          fn = 0;
        JvmMethodAnalysis ann;
        std::unordered_map<uint64_t, std::string> inlineEffect;  // bci -> stack effect text
        std::unordered_map<uint64_t, std::string> inlineBranch;  // bci -> branch meaning
        std::unordered_map<uint64_t, int>         depthBefore;   // bci -> operand-stack depth
    };
    std::list<JvmAnnEntry>  jvmAnnLru_;
    uint64_t                jvmAnnSig_ = ~0ull;
    int                     jvmMethodSel_ = -1;   // Java tab: selected note/method row
    char                    jvmCpFilter_[64] = "";
    const JvmAnnEntry* jvmAnnotationsFor(AppContext& ctx, uint64_t va, bool buildIfMissing);
    void renderJavaTab(AppContext& ctx);        // "Java" lower sub-tab (static .class / JVM)
    void renderGameMakerTab(AppContext& ctx);
    void toggleGmlBreakpoint(AppContext& ctx, uint64_t fileOffset);
    void addGmlBreakpoints(AppContext& ctx, const std::vector<uint64_t>& fileOffsets);
    bool hasGmlBreakpoint(const AppContext& ctx, uint64_t fileOffset) const;
    std::shared_ptr<const GameMakerArchive> gmlArchiveView_;
    char gmlFilter_[256] = "";
    std::string gmlFilterApplied_;
    int gmlBrowseKind_ = 0, gmlBrowseKindApplied_ = -1;
    int gmlSelectedObject_ = -1;
    std::vector<uint32_t> gmlFilteredRows_;
    std::vector<GmlSavedWatch> gmlTransientWatches_;
    GmlPauseIdentity gmlEditOwner_{};
    uint64_t gmlEditRevision_ = 0;
    uint32_t gmlEditSlot_ = UINT32_MAX;
    uint64_t gmlSelectedFrameId_ = 0;
    uint64_t gmlSelectedInstanceId_ = 0;
    GmlPauseIdentity gmlWatchInspectionOwner_{};
    uint64_t gmlWatchInspectionRevision_ = 0;
    std::unordered_set<uint32_t> gmlWatchInspectedObjects_;
    char gmlEditText_[128] = "";

    // Game/crackme context (additions.md D/H): grouped strings, likely gameplay
    // functions, runtime boundaries, and "where to start" hints. The analyzer is
    // pure Core; the UI only adapts current tab state into GameContextInput.
    GameContextReport gameCtx_;
    uint64_t          gameCtxSig_ = ~0ull;
    char              gameCtxFilter_[64] = "";
    CrackmeTriageResult crackmeTriage_;
    bool              crackmeTriageValid_ = false;
    bool              crackmeTriagePending_ = false;
    uint64_t          crackmeTriageGen_ = 0;
    int               crackmeTriageEndpointSel_ = -1;
    int               crackmeAuthorizationFlowSel_ = -1;
    int               crackmeAuthorizationPredicateSel_ = -1;
    int               crackmeAuthorizationUseSel_ = -1;
    int               crackmeAuthorizationStringAnchorSel_ = -1;
    int               crackmePersistentStateSel_ = -1;
    bool              authorizationWatchPauseOnHit_ = false;
    bool              authorizationWatchAlsoNetwork_ = false;
    std::string       authorizationWatchError_;
    AuthorizationExperiment authorizationExperiment_;
    std::string       authorizationExperimentError_;
    uint64_t gameContextSig(AppContext& ctx) const;
    const GameContextReport& gameContextFor(AppContext& ctx);
    void renderGameContextTab(AppContext& ctx);

    // Watch expressions (lower "Watch" sub-tab): evaluated while paused via the
    // conditional-breakpoint expression evaluator. Persist via ctx.staticProject().watches.
    // Each expression is compiled ONCE (watchProgs_, parallel to watches_) and
    // evaluated per frame via EvalCompiled; watchOk_[i] = parsed successfully.
    std::vector<std::string> watches_;
    std::vector<CondOperand> watchProgs_;   // parallel to watches_ (compiled once)
    std::vector<bool>        watchOk_;      // parallel: expression parsed OK
    char                     watchEntry_[160] = "";
    void recompileWatches();                // refill watchProgs_/watchOk_ from watches_

    // ---- clean-room synthesis ("Synthesis" lower tab) ----
    SynthResult synth_;
    bool        synthHave_    = false;
    bool        synthPending_ = false;  // a K_Synthesis worker job is in flight
    bool        synthFocus_   = false;  // focus the Synthesis tab next frame

    // ---- hot-patch editor ("Hot-Patch" lower tab) ----
    uint64_t    hotSiteVA_  = 0;
    bool        hotSiteValid_ = false; // selected site may legitimately be VA 0
    uint32_t    hotOrigLen_ = 0;
    int         hotLang_    = 0;        // 0=asm 1=C
    char        hotEditor_[8192] = "";
    std::string hotStatus_;
    bool        hotFocus_   = false;

    // ---- path explorer ("Path Explorer" lower tab) ----
    PathTree    pathTree_;
    bool        pathHave_    = false;
    bool        pathPending_ = false;   // a K_PathExplore worker job is in flight
    std::string pathStatus_;
    bool        pathFocus_   = false;
};

} // namespace ds
