#pragma once
#include "ITab.h"
#include "../Core/ProcessManager.h"    // ModuleInfo (Functions sub-tab)
#include "../Core/SymbolResolver.h"    // DbgHelp / PDB symbol names
#include "../Core/XrefIndex.h"         // whole-program cross-reference index (Xrefs tab)
#include "../Core/AlgoScan.h"          // AlgoMatch (Algorithms sub-tab / K_Intent results)
#include "../Core/CFG.h"               // ControlFlowGraph (cached CFG graph view)
#include "../Core/Decompiler.h"        // DecompResult (pseudocode + per-line VA map)
#include "../Core/FuncAnnotate.h"      // FuncAnnotations ("Annotations" lower tab + inline notes)
#include "../Core/GameContext.h"       // game/crackme workflow context panel
#include "../Core/JvmAnnotate.h"       // JvmMethodAnalysis ("Java" lower tab + inline stack effects)
#include "../Core/Synthesis.h"         // SynthResult ("Synthesis" lower tab)
#include "../Core/PathExplore.h"       // PathTree ("Path Explorer" lower tab)
#include "../Core/Cond.h"              // CondOperand (compiled Watch expressions)
#include <cstdint>
#include <deque>
#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ds {

// Binary View: the central workspace. Three synchronized views (assembly,
// pseudocode, raw bytes) plus a side panel of bookmarks / functions / strings,
// byte-pattern search, and lower sub-tabs for breakpoints / notes / results /
// hotkeys.
class BinaryViewTab final : public ITab {
public:
    const char* name() const override { return "Binary View"; }
    void render(AppContext& ctx) override;

    // Symbol entries exposed to the command palette: address + display name +
    // a pre-lowercased copy for fuzzy matching. Backed by the signature-cached
    // goto-symbol index (rebuilt only when the target/process changes).
    struct SymEntry {
        uint64_t addr;
        std::string name;
        std::string lower;
        bool live = false; // runtime address (live module export) vs file/project VA
    };
    const std::vector<SymEntry>& paletteSymbols(AppContext& ctx) {
        buildSymbolIndex(ctx);
        return symbolIndex_;
    }

private:
    void renderWelcome(AppContext& ctx);
    void renderAssembly(AppContext& ctx);          // dispatcher: full-program or windowed
    void renderAssemblyWindow(AppContext& ctx);    // ~256 instructions around the cursor
    void renderAssemblyFull(AppContext& ctx);      // entire program, clipper-rendered
    void buildFullListing(AppContext& ctx);        // linear sweep of all code sections (cached)
    uint64_t listingSig(AppContext& ctx) const;    // cache key for listRows_ (image/funcs/strings/arch/engine)
    void renderAsmFuncHeader(AppContext& ctx, uint64_t addr);
    void renderAsmRow(AppContext& ctx, const Instruction& in, const struct DbgSnapshot& snap,
                      const std::string& hoverTok, std::string& nextHoverTok, bool autoScrollHere);
    void selectRange(uint64_t a, uint64_t b);                              // fill selVAs_ over [a,b] in listing order
    void asmSelectionMenu(AppContext& ctx, const struct DbgSnapshot& snap); // batch actions over selVAs_ (static listing)
    void liveSelectionMenu(AppContext& ctx, const struct DbgSnapshot& snap); // batch actions over selVAs_ (live listing)
    void emitInstrCopyMenu(const Instruction& in);                          // shared Copy bytes/C-array/instruction (static + live menus)
    void stepAsmCursor(int delta);                                         // move the cursor +/- N instructions over listRows_
    void drawAsmArrows(float x0, float y0, float x1, float y1);            // branch arrows in the static flow gutter (table body rect)
    void revertPatchAt(AppContext& ctx, uint64_t va);                      // restore a recorded patch's original bytes
    void renderLiveAssembly(AppContext& ctx);
    void renderLiveListing(AppContext& ctx, const struct DbgSnapshot& snap, uint64_t start);
    void renderLivePseudocode(AppContext& ctx, const struct DbgSnapshot& snap, uint64_t start);
    void renderRegisterBox(AppContext& ctx, const struct DbgSnapshot& snap);
    void renderLiveSearchPopup(AppContext& ctx);
    void renderPatchPopup(AppContext& ctx);
    void applyPatchBytes(AppContext& ctx, uint64_t va, std::vector<uint8_t> bytes,
                         uint32_t origLen, bool padNop);   // record patch + live-write if attached
    // Canonical (file-VA) key a patch is stored under, translating a runtime VA
    // from the live listing back to file space when attached under ASLR.
    uint64_t patchKeyFor(AppContext& ctx, uint64_t va);
    std::string buildSignature(AppContext& ctx, uint64_t lo, uint64_t hi,
                               bool live, bool wildcard);   // instruction span -> "48 8B ?? .." pattern
    void renderXrefPopup(AppContext& ctx);
    void startXrefSearch(AppContext& ctx, uint64_t target);
    void analyzeAllModules(AppContext& ctx);   // read every module's image (off-thread) + analyze each
    void restoreFromModuleCache(AppContext& ctx, struct LoadedModule& m);  // instant switch to a pre-analyzed module
    void buildXrefIndex(AppContext& ctx);      // (re)build the whole-program xref index from the file image (UI-thread fallback)
    bool ensureXrefReady(AppContext& ctx);     // true if the index is current; else kicks an off-thread K_Xref build
    uint64_t xrefSig(AppContext& ctx);         // content signature the xref index is cached by
    void renderXrefsTab(AppContext& ctx);      // "Xrefs" lower sub-tab: who references the cursor / its function
    void exportAnalysis(AppContext& ctx);      // File > Export Analysis: write Markdown/HTML report
    std::string decompileFunctionText(AppContext& ctx, uint64_t fnStart, uint32_t fnSize); // structured pseudo-C for one fn
    void requestFunctionDecompile(AppContext& ctx, uint64_t fnStart, uint32_t fnSize,
                                  size_t availableBytes); // queue named/signature-aware worker decompile
    const DecompResult* decompLruGet(uint64_t va);                // recently-decompiled cache lookup (nav back/fwd)
    void                decompLruPut(uint64_t va, const DecompResult& r);
    std::string symbolFor(AppContext& ctx, uint64_t addr);   // address -> function/export name
    // Per-stop memo key (register snapshot + liveGen_ + state). Shared by the live-view
    // caches (ptrDescCache_, strCmtCache_) so they invalidate together on step / re-stop / edit.
    uint64_t liveStopKey(const struct DbgSnapshot& snap) const;
    // Live view: describe what a register/stack value points to (string / symbol / ->string),
    // or "" if it isn't a meaningful pointer. Reads debuggee memory; only valid while paused.
    std::string describePointer(AppContext& ctx, const struct DbgSnapshot& snap, uint64_t v);
    // Runtime<->file image-base translation for the main module. Under ASLR the
    // process loads the image at a base != the file's preferred imageBase, so
    // file-keyed data (analyzed functions, persisted comments/renames) must be
    // shifted by this delta to line up with live instruction addresses. All three
    // are no-ops (return the input) when not attached or the base is unknown.
    uint64_t liveMainBase(AppContext& ctx);                  // runtime base of the attached main module, 0 if unknown
    uint64_t fileVAtoLive(AppContext& ctx, uint64_t fileVA); // file VA -> runtime VA
    uint64_t liveVAtoFile(AppContext& ctx, uint64_t liveVA); // runtime VA -> file VA
    void renderCallStack(AppContext& ctx);
    void renderStackTab(AppContext& ctx);   // annotated live stack dump (RSP/RBP, symbols, strings)
    void computeCallStack(AppContext& ctx, const struct DbgSnapshot& snap);
    void renderGotoPopup(AppContext& ctx);
    void buildSymbolIndex(AppContext& ctx);
    bool lookupSymbol(AppContext& ctx, const char* name, uint64_t& addressOut);
    void startTextSearch(AppContext& ctx);                      // search disassembly text
    void renderTextSearchPopup(AppContext& ctx);
    // Render text as hover-highlightable tokens: matches of `hl` get a background;
    // a hovered word token is written to `nextHover` (for next frame's highlight).
    void renderHoverTokens(const char* s, unsigned int col, const std::string& hl, std::string& nextHover);
    void renderPseudocode(AppContext& ctx);
    void renderDecompiler(AppContext& ctx);   // side-by-side decompiled pseudo-C | synced asm pane
    void renderHex(AppContext& ctx);
    void hexCommitByte(AppContext& ctx, uint64_t off, uint8_t value);   // route an edit into the patch system
    void renderGraph(AppContext& ctx);
    void renderCallGraph(AppContext& ctx);             // callers/callees around the cursor fn
    void buildCallGraph(AppContext& ctx);              // cached call edges between functions (UI-thread fallback)
    bool ensureCallGraphReady(AppContext& ctx);        // true if current; else kicks an off-thread K_CallGraph build
    std::string guessSignature(AppContext& ctx, uint64_t fnStart, uint32_t fnSize); // best-effort
    // Resolve a constant data address to a decompiler token (quoted string literal,
    // import/global name), or "" if not meaningful. `live` reads process memory.
    std::string dataRefToken(AppContext& ctx, uint64_t va, bool live);
    std::vector<uint64_t> resolveJumpTable(AppContext& ctx, const Instruction& in); // switch tables
    void renderSidePanel(AppContext& ctx);
    void renderLowerTabs(AppContext& ctx);
    void renderExportsTab(AppContext& ctx);             // complete PE EAT browser (aliases/ordinals/forwarders)
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
    void loadProjectState(AppContext& ctx);     // ctx.project -> tab members (on open)
    void saveProjectState(AppContext& ctx);     // tab members -> ctx.project (each frame)
    std::string annName(AppContext& ctx, uint64_t addr);  // user rename for addr, or ""
    void runByteSearch(AppContext& ctx);
    void analyzeFunctions(AppContext& ctx);            // run FunctionAnalyzer -> functions_ list
    void guessFunctionNames(AppContext& ctx);          // heuristically name sub_ functions (read_file, j_CreateFileW, ...)
    void scanStrings(AppContext& ctx);                 // ASCII/UTF-8 + UTF-16LE -> strings_ list
    void onBinaryLoaded(AppContext& ctx);              // re-home cursor to entry point + auto-analyze
    void liveNavigate(uint64_t va);    // set cursor + record back/forward history (alias of navigateTo)
    void navigateTo(uint64_t va);      // unified: move cursor + push back/forward history
    // Navigate to a FILE-space address from a side panel / list (functions, bookmarks,
    // imports, ...): records history, and in the live view translates to the runtime VA.
    void gotoStatic(AppContext& ctx, uint64_t fileVA);
    void gotoExportTarget(const BinaryFile::Export& ex); // code -> Assembly, mapped data -> Hex
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
    };
    struct CallFrame { uint64_t pc; uint64_t frameSp; std::string name; };

    uint64_t cursorVA_  = 0;     // current focus address (VA 0 is valid when cursorValid_)
    bool     cursorValid_ = false;
    int      mainView_  = 0;     // 0=asm 1=pseudo 2=hex 3=cfg 4=live asm 5=callgraph

    // The body is a FIXED wireframe layout (disassembler-wireframes.html .wf-body.va):
    // LEFT side panel | CENTER code views | GRAPH column | RIGHT register rail, over a
    // BOTTOM debug dock. Each region is a bordered child (a .wf-panel); the column
    // widths + dock height below are drag-resizable (VSplitter / a local HSplitter) and
    // persist across frames. layoutScaled_ guards the one-time HiDPI scaling of the
    // pixel defaults (replaces the old DockSpace's dockInitDone_ role).
    bool     dockInitDone_    = false;   // retained (unused by the fixed layout)
    bool     layoutScaled_    = false;   // multiply the width defaults by UiScale() once
    float    leftColW_    = 218.0f;      // .va-left  side panel width
    float    graphColW_   = 400.0f;      // .va-graphcol CFG/Call-Graph column width
    float    rightRailW_  = 250.0f;      // .va-rightrail Registers/Stack width
    float    bottomDockH_ = 200.0f;      // .wf-bottomdock lower-tabs height
    int      graphView_   = 0;           // graph column tab: 0 = CFG, 1 = Call Graph
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
    float    decompSplitW_ = 360.0f;     // pseudo pane width (decompiler view)
    uint64_t decompHoverVA_ = 0;         // VA cross-highlighted between the two panes

    // Multi-line selection in the full assembly listing: click = single,
    // Shift+click = range from the anchor, Ctrl+click = toggle one line.
    std::unordered_set<uint64_t> selVAs_;
    uint64_t                     selAnchorVA_ = 0;
    bool                         selAnchorValid_ = false;
    int                          selView_ = -1;   // which listing (0=static,4=live) owns the current selection

    // Full-program listing: a cached row index (instruction addresses + function
    // divider markers) over all executable sections, rendered with a clipper.
    // String literals from non-executable (data) sections are also emitted as
    // `strData` rows (strIdx -> strings_) so the listing can scroll to a clicked
    // string, which otherwise lives outside the code rows. Rows are kept sorted
    // ascending by addr (sections are walked in VA order) for the scroll search.
    struct ListRow { uint64_t addr; bool divider; bool strData = false; int strIdx = -1; };
    std::vector<ListRow> listRows_;
    bool                 listBuilt_     = false;
    uint64_t             listSig_       = 0;
    int                  listInsnCount_ = 0;
    bool                 asmFullProgram_ = true;

    // Render-thread-only cache of decoded visible rows: the full listing stores only
    // addresses and re-decodes per visible row every frame, so a fast scroll redecodes
    // the same ~50 rows repeatedly. Keyed by VA; the whole cache is dropped when the
    // image (load/patch), arch, or engine changes (decodeCacheKey_). Bounded by FIFO:
    // when it exceeds the cap, the oldest insertions are evicted (decodeOrder_) instead
    // of clearing wholesale, so a long fast-scroll keeps recent rows warm.
    static constexpr size_t kDecodeCacheCap = 32768;
    std::unordered_map<uint64_t, Instruction> decodeCache_;
    std::deque<uint64_t>                      decodeOrder_;   // insertion order for FIFO eviction
    uint64_t                                  decodeCacheKey_ = ~0ull;
    // Windowed assembly decodes up to 256 instructions. Cache that whole window
    // while the cursor/image/function bounds are unchanged instead of repeating
    // alignment, allocation, decode, and function-set construction every frame.
    uint64_t                                  asmWindowKey_ = ~0ull;
    uint64_t                                  asmWindowCursor_ = ~0ull;
    std::vector<Instruction>                  asmWindowInsns_;
    std::unordered_set<uint64_t>              asmWindowFuncSet_;
    bool                 functionsDirty_ = false;   // a patch changed code: re-run analyzeFunctions before the next decompile/CFG

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
    void  drawRowGlows(float x0, float y0, float x1, float y1);   // paint + clear rowGlow_
    void  pushRowGlow(float yCenter, bool rowAtRip, bool rowSel, bool rowJump, float flash);
    float navFlashAt(uint64_t addr);   // 1..0 decaying flash if addr was just navigated to
    uint64_t hlJumpVA_   = 0;          // branch target of the cursor's instruction (per frame)
    bool     hlJumpValid_ = false;     // target VA 0 is representable
    uint64_t navFlashVA_ = 0;          // navigation arrival flash target (VA 0 allowed)
    bool     navFlashValid_ = false;
    double   navFlashT0_ = 0.0;        // ImGui::GetTime() when the flash started
    bool     followLiveRip_ = true;
    char     gotoBuf_[32] = "";
    char     byteSearch_[128] = "";
    std::vector<uint64_t> searchHits_;
    bool     byteSearchLive_ = false;  // search debuggee memory instead of the file

    // ---- Live disassembly view state ----
    int       liveMode_       = 0;     // 0 = disassembly, 1 = pseudocode
    bool      showRegBox_     = true;  // compact register box, top-right of the view
    bool      showJumpArrows_ = true;  // branch arrows drawn in the flow gutter
    bool      showRegHints_   = true;  // inline "rax=0x..." hints on the RIP row
    Registers regsAtLastStop_{};       // registers captured at the current stop
    Registers regsAtPrevStop_{};       // ...and the one before, for change tinting
    // Inline editing in the Registers tab (only while Paused). -1/0 = not editing.
    int       regEditIdx_   = -1;      // index into the register table being edited
    char      regEditBuf_[20] = "";
    bool      regEditFocus_ = false;
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
    uint64_t  lastScrolledRip_ = 0;    // focus addr we last auto-scrolled to (live view)
    uint64_t  lastAsmScroll_   = 0;    // last centered static VA
    bool      lastAsmScrollValid_ = false;
    // Back/forward history. Each entry remembers whether it was a LIVE (runtime VA,
    // shown in the live view) or STATIC (file VA) location, so navBack/navForward
    // restore the right view instead of feeding a runtime VA into a file-VA view.
    struct NavEntry { uint64_t va; bool live; };
    std::vector<NavEntry> navHist_;    // cursor history (back/fwd)
    int                   navPos_ = -1;

    // Live listing decode cache: re-disassembling the on-screen window every frame
    // churned the heap (the working set climbed while attached). The decode + index
    // + function-divider set are rebuilt only when the signature below changes.
    std::vector<uint8_t>              liveBuf_;         // reused read scratch (never realloc'd per frame)
    std::vector<Instruction>         liveInsns_;        // cached decode of the current window
    std::unordered_map<uint64_t,int> liveIdxOf_;        // address -> index within liveInsns_
    std::unordered_set<uint64_t>     liveFuncSet_;      // divider addresses (runtime VAs)
    uint64_t                         liveCacheStart_ = 0;
    uint64_t                         liveCacheSig_   = ~0ull;
    uint32_t                         liveGen_        = 0;  // bumped on live write / patch / re-analyze / detach
    bool                             wasAttached_    = false; // detach-edge detector (clear caches once)
    bool                             runtimeBannerDismissed_ = false; // runtime-wrapper/archive banner [x], reset per load

    // Decoder for the LIVE view, selected to match the DEBUGGEE's bitness. The static
    // ctx.disasm follows the loaded file's arch, which can differ from the attached
    // process (e.g. a 32-bit WOW64 target debugged while an x64 file — or no file — is
    // loaded). Rebuilt only when the bitness changes; falls back to ctx.disasm.
    std::unique_ptr<IDisassembler>   liveDisasm_;
    int                              liveDisasmArch_   = -1; // Arch of liveDisasm_, -1 = none built
    int                              liveDisasmEngine_ = -1; // Engine of liveDisasm_ (a UI engine switch rebuilds it)
    IDisassembler*                   liveDecoder(AppContext& ctx, bool is32);

    // Live process search (strings / hex / values in committed memory).
    char                  liveFind_[128] = "";
    int                   liveFindKind_  = 0;   // 0=ASCII 1=UTF-16 2=hex 3=u64
    std::vector<uint64_t> liveFindHits_;
    std::string           liveFindStatus_;
    bool                  openFindPopup_ = false;

    // Live patching (write bytes straight into the debuggee).
    int                   patchMode_ = 1;       // 0 = hex bytes, 1 = assembly (Keystone)
    uint64_t              patchVA_  = 0;
    uint32_t              patchLen_ = 0;
    char                  patchHex_[128] = "";
    char                  patchAsmText_[256] = "";
    std::string           patchAsm_;            // disasm preview of edited bytes
    std::string           patchStatus_;
    std::string           runErr_;               // last "> Run" launch error, shown in the asm toolbar
    bool                  openPatchPopup_ = false;
    bool                  patchPadNop_ = true;   // NOP-pad a short encoding up to the original length
    int                   hwSizeSel_   = 1;      // data-breakpoint length (1/2/4/8) chosen in the HW submenu

    // Functions / modules browser (lower "Functions" sub-tab).
    std::vector<ModuleInfo> liveModules_;
    uint32_t                liveModulesPid_ = 0;
    uint64_t                liveMainBase_    = 0;   // cached runtime base of the main module
    uint32_t                liveMainBasePid_ = 0;   // pid the cache was computed for
    char                    funcTabFilter_[64] = "";
    std::vector<int>        funcTabVisible_;          // cached lower Functions-tab filter result
    char                    funcTabFilterLast_[64] = "\x01";
    uint64_t                funcTabVisSig_ = ~0ull;

    // Pseudocode cache (regenerated when the function or RIP context changes).
    uint64_t              pseudoVA_ = 0;
    std::string           pseudoText_;

    // Decompiler (structured pseudo-C) for the static Pseudocode view. The decompile
    // runs off the render thread (K_Decompile); decompVA_ is the function currently
    // shown when decompValid_ is true (VA 0 is valid), decompText_ its result, and
    // decompPending_ true while the worker is running.
    // decompLines_/decompLineVA_ are decompText_ split per line + the per-line source
    // VAs (DecompResult::lineVA; 0 = synthetic) backing click-to-navigate.
    // decompLru_ keeps the few most-recently decompiled functions so nav back/forward
    // is instant (no re-decompile); a small linear list (front = most recent), capped.
    uint64_t              decompVA_ = 0;
    bool                  decompValid_ = false;
    std::string           decompText_;
    std::vector<std::string> decompLines_;
    std::vector<uint64_t>    decompLineVA_;
    bool                  decompPending_ = false;
    static constexpr size_t kDecompLruCap = 16;
    std::list<std::pair<uint64_t, DecompResult>> decompLru_;
    std::shared_ptr<const DecompileNameMap> decompNamesSnapshot_; // reused across function navigation
    uint64_t              decompNamesFunctionsGen_ = ~0ull;
    uint32_t              decompNamesNamesGen_ = ~0u;
    void setDecompContent(std::string text, std::vector<uint64_t> lineVA);
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

    // User annotations (persist via ctx.project). comments_ render in the
    // listing; names_ override symbol resolution everywhere names appear.
    std::unordered_map<uint64_t, std::string> comments_;
    std::unordered_map<uint64_t, std::string> names_;
    // Resolved PE imports: IAT slot VA -> "dll.func" (built on load from the
    // BinaryFile import table), so call/jmp through the IAT shows the API name.
    std::unordered_map<uint64_t, std::string> importMap_;
    char                  importFilter_[64] = "";
    char                  exportFilter_[96] = "";
    char                  exportFilterLast_[96] = "\x01";
    std::vector<int>      exportVisible_;
    uint64_t              exportVisSig_ = ~0ull;
    size_t                exportCodeCount_ = 0;
    size_t                exportForwardCount_ = 0;
    size_t                exportDataCount_ = 0;
    size_t                exportUnmappedCount_ = 0;
    // Comment / rename / breakpoint-condition edit popups.
    uint64_t              annPopupVA_ = 0;
    char                  commentBuf_[512] = "";
    char                  renameBuf_[128]  = "";
    char                  condPopupBuf_[160] = "";
    bool                  openCommentPopup_ = false;
    bool                  openRenamePopup_  = false;
    bool                  openCondPopup_    = false;
    bool                  projectLoaded_    = false;  // loadProjectState ran for this image
    bool                  projectDirty_     = false;  // an annotation changed: mirror to ctx.project this frame

    // Inline string/data comments + cross-reference (xref) search.
    bool                  showStringComments_ = true;
    bool                  showHints_          = true;   // inline "what it does" gloss per instruction
    uint64_t              xrefTarget_ = 0;
    std::vector<uint64_t> xrefHits_;
    bool                  xrefHitsLive_ = false;   // hits are runtime VAs (searched the debuggee)
    std::string           xrefStatus_;
    bool                  openXrefPopup_ = false;
    // Attached xref search runs off the render thread on LiveScanService; this token
    // matches the in-flight request so a stale/older sweep's result is ignored.
    bool                  xrefScanning_ = false;
    uint64_t              xrefToken_    = 0;
    // Whole-program xref index (sources per target), built lazily from the on-disk
    // image and cached by the listing content signature; powers the "Xrefs" tab.
    XrefIndex             xrefIndex_;
    uint64_t              xrefIndexSig_ = ~0ull;
    uint64_t              xrefRequestedSig_ = ~0ull;   // last sig we asked the worker to index (dedup re-requests)
    // Analysis export (File > Export Analysis) result, shown in a small popup.
    std::string           exportStatus_;
    bool                  openExportPopup_ = false;

    // Symbol / function-name resolution.
    bool                  showNames_ = true;   // resolve call/jmp targets to names
    bool                  symAttached_ = false;// cached once per frame (avoid re-locking debug snapshot)
    uint32_t              symPid_ = 0;
    const DbgSnapshot*    frameSnap_ = nullptr; // borrowed App render snapshot (or fallback below)
    DbgSnapshot           fallbackFrameSnap_;  // standalone/test render fallback
    // Parsed export tables for live modules: base -> sorted (va, name).
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t, std::string>>> modExports_;
    SymbolResolver                              symbols_;     // DbgHelp / PDB names
    std::unordered_map<uint64_t, std::string>   symCache_;    // addr -> resolved name (per session)
    bool                                        symSessionLive_ = false;

    // Call stack (real DbgHelp StackWalk64 unwind from the debugger when available,
    // else a heuristic RSP/RBP scan). Recomputed per stop.
    std::vector<CallFrame> callStack_;
    bool                   callStackReal_ = false;   // true = real unwind, false = heuristic
    uint64_t               callStackSig_ = 0;
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

    // Disassembly text search (mnemonic / operands).
    char                  textSearch_[128] = "";
    bool                  textCaseSensitive_ = false;
    std::vector<uint64_t> textHits_;
    bool                  textHitsLive_ = false;   // hits are runtime VAs (searched the debuggee)
    std::string           textStatus_;
    bool                  openTextPopup_ = false;

    // Highlight-on-hover: the token under the mouse last frame (live + static disasm).
    std::string           hoverToken_;

    // CFG graph: per-block manual drag offsets (block start VA -> dx, dy).
    std::unordered_map<uint64_t, std::pair<float, float>> cfgDrag_;
    // Cached CFG for the graph view. BuildCFG decodes up to 1500 instructions and runs
    // dominator/loop analysis, so rebuild only when the root VA, decoder, or code-window
    // bytes change (see renderGraph) rather than every frame.
    ControlFlowGraph      cfgCache_;
    uint64_t              cfgCacheSig_ = ~0ull;

    // Call graph: cached call edges between discovered functions (fn -> callees,
    // and the reverse). Rebuilt when the function set changes.
    std::unordered_map<uint64_t, std::vector<uint64_t>> callees_;
    std::unordered_map<uint64_t, std::vector<uint64_t>> callers_;
    uint64_t              callGraphSig_ = ~0ull;
    uint64_t              callGraphRequestedSig_ = ~0ull;   // last sig asked of the worker (dedup re-requests)

    std::vector<Bookmark> bookmarks_;
    std::unordered_set<uint64_t> breakpoints_;   // O(1) membership in the hot render path
    std::vector<Strng>    strings_;
    std::vector<Func>     functions_;
    // Sorted (address -> index into functions_) lookup, rebuilt lazily when the
    // function set changes. Lets symbolFor / status bar / live views find the
    // function containing an address by binary search instead of a linear scan.
    std::vector<std::pair<uint64_t,int>> funcIndex_;
    bool                                 funcIndexDirty_ = true;
    const Func* funcContaining(uint64_t addr);   // greatest function start <= addr (binary search), or nullptr
    std::unordered_map<uint64_t, std::string> condBuf_; // per-bp condition edit text
    std::unordered_map<uint64_t, uint32_t> everyNBuf_;  // per-bp "break every Nth hit" (0/1 = every)
    char                  fcCodeBuf_[16] = "";          // first-chance whitelist hex-code entry
    size_t                dbgOutSeen_ = 0;              // Debug Output auto-scroll watermark
    // Heuristic function naming: address -> the basis for the guessed name (tooltip).
    // Guesses live in Func::name (so they flow through symbolFor everywhere) but are
    // never persisted — they are recomputed from the image on each analyze.
    std::unordered_map<uint64_t, std::string> guessReason_;
    bool                  guessNames_ = true;    // run the name guesser after analysis
    std::string           fnSummary_;
    char                  fnFilter_[64] = "";
    char                  strFilter_[64] = "";
    // Filtered row indices for the side lists, clipper-rendered (these lists can hold
    // thousands of entries; rendering all of them was wasteful). Rebuilt ONLY when the
    // filter text or the underlying data changes — not every frame — since the rebuild
    // copies a std::string + probes the rename map per function (see fnVisSig_).
    std::vector<int>      fnVisible_;
    std::vector<int>      strVisible_;
    std::vector<int>      impVisible_;
    char                  fnFilterLast_[64] = "\x01";   // sentinel != "" forces a first build
    char                  strFilterLast_[64] = "\x01";
    uint64_t              fnVisSig_  = ~0ull;   // data signature of fnVisible_'s last build
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
    uint32_t              stringsAutoPid_ = 0;     // pid we already auto-scanned live strings for
    char                  notes_[4096] = "";

    // Algorithm recognition (AlgoScan / K_Intent): crypto/encoding matches from the
    // background recognizer, shown in the "Algorithms" lower sub-tab. algoLabels_ is the
    // user-confirmed evidence overlay, persisted via ctx.project.algorithmLabels (matches
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

    // Game/crackme context (additions.md D/H): grouped strings, likely gameplay
    // functions, runtime boundaries, and "where to start" hints. The analyzer is
    // pure Core; the UI only adapts current tab state into GameContextInput.
    GameContextReport gameCtx_;
    uint64_t          gameCtxSig_ = ~0ull;
    char              gameCtxFilter_[64] = "";
    uint64_t gameContextSig(AppContext& ctx) const;
    const GameContextReport& gameContextFor(AppContext& ctx);
    void renderGameContextTab(AppContext& ctx);

    // Watch expressions (lower "Watch" sub-tab): evaluated while paused via the
    // conditional-breakpoint expression evaluator. Persist via ctx.project.watches.
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
    uint32_t    hotOrigLen_ = 0;
    int         hotLang_    = 0;        // 0=asm 1=C 2=Python
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
