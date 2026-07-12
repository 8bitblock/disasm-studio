#pragma once
//
// AnalysisJobs.h
// Pure (ImGui-free, Win32-free) analysis passes extracted from BinaryViewTab so the
// expensive load-time work can run on a background worker (AnalysisService) and be
// unit-tested in isolation. Each function reads a BinaryFile (and, where it must
// decode, an injected IDisassembler) and returns plain result data — it never
// touches UI state, the debugger, or a shared decoder.
//
// These mirror BinaryViewTab::scanStrings (file mode), analyzeFunctions +
// guessFunctionNames, and buildFullListing respectively; keep them in lock-step
// with those if the originals change.
//
#include "Decompiler.h"   // DecompResult (DecompileRegion's text + per-line VA map)

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ds {

class BinaryFile;
class IDisassembler;
enum class Arch;
struct XrefIndex;
struct AlgoMatch;

// A corrupt/resource-heavy image can contain millions of tiny runs. Keep scans
// bounded at a high, explicit limit which the clipper-rendered UI can handle.
inline constexpr size_t kDefaultStringScanCap = 100000;

// One extracted printable string (parallels BinaryViewTab::Strng). A pathological
// individual run is retained as a bounded prefix; textTruncated makes that honest.
struct StrResult {
    uint64_t    address       = 0;
    std::string text;
    bool        wide          = false;
    bool        textTruncated = false;
};

// One discovered + optionally heuristically-named function
// (parallels BinaryViewTab::Func plus its guessReason_ entry).
struct FuncResult {
    uint64_t    address = 0;
    uint32_t    size    = 0;
    std::string name;
    bool        guessed = false;
    std::string reason;   // basis for a guessed name (tooltip); "" when not guessed
    bool        isExport = false; // authoritative loader/PDB-style name; never replace
};

// One row of the full-program listing index (parallels BinaryViewTab::ListRow).
struct ListRowR { uint64_t addr = 0; bool divider = false; bool strData = false; int strIdx = -1; };

// One directed call edge between two discovered functions (caller -> callee). The
// UI folds these into its callees_/callers_ adjacency maps.
struct CallEdgeR { uint64_t from = 0, to = 0; };

struct AnalyzeOut {
    std::vector<FuncResult> functions;   // sorted by address (FunctionAnalyzer order)
    std::string             summary;
};

// Immutable address->display-name snapshot supplied to an off-thread decompile.
// The UI builds this from discovered/guessed functions plus analyst renames, so
// the worker never reaches into mutable tab/project state.
using DecompileNameMap = std::unordered_map<uint64_t, std::string>;

// Extract ASCII/UTF-8 + UTF-16LE printable runs (>= 4 characters) from the file
// image, mapping offsets through offsetToVA. Returned sorted by address and capped.
// `truncated`, when non-null, reports that additional results existed past the cap.
// This is the FILE-mode scan; live/debuggee buffers use ScanStringsBuffer on the
// LiveScanService worker.
// `progress`, when non-null, is set to the number of image bytes scanned so far
// (a background worker publishes it for a progress bar; never read by this fn).
std::vector<StrResult> ScanStringsImage(const BinaryFile& bin,
                                        size_t cap = kDefaultStringScanCap,
                                        std::atomic<uint32_t>* progress = nullptr,
                                        bool* truncated = nullptr);

// Append ASCII/UTF-8 + UTF-16LE printable runs (>= 4 chars) found in the raw buffer
// [d, d+n) to `out`, mapping a buffer offset k to the virtual address (base + k).
// Stops once `out` reaches `cap`. `truncated`, when non-null, reports that this
// buffer contained an additional result which did not fit. This is the primitive
// behind the live (debuggee-memory) scan on the LiveScanService worker. The caller
// sorts/de-dups across buffers. Pure (no UI/Win32).
void ScanStringsBuffer(const uint8_t* d, size_t n, uint64_t base,
                       std::vector<StrResult>& out,
                       size_t cap = kDefaultStringScanCap,
                       bool* truncated = nullptr);

// Discover functions (FunctionAnalyzer) and, when `guessNames`, apply the heuristic
// namer (FunctionNamer) using the binary's imports + the provided strings. `strings`
// must be sorted by address (as ScanStringsImage returns) so the string-reference
// lookup can binary-search.
AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames);

// Exact-architecture form used by AnalysisService. This matters for raw blobs:
// their bytes carry no machine field, while x86 prologue signatures must never
// be applied to an ARM/MIPS/PPC/RISC-V selection.
AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames,
                                 Arch arch);

// Build the linear-sweep listing row index over every section in VA order (a
// divider row at each function start + one row per decoded instruction in the
// executable sections; one `strData` row per string literal inside the
// non-executable data sections, so the listing can scroll to a clicked string).
// `strings` must be sorted by address (as ScanStringsImage returns); strIdx
// indexes into it. Capped at `cap` instructions. `cancelled`, when set, is polled
// periodically; returning true aborts early (drops a superseded job). `progress`,
// when non-null, is set to the running instruction count (background progress bar).
std::vector<ListRowR> BuildListingRows(const BinaryFile& bin, IDisassembler& dis,
                                       const std::vector<uint64_t>& funcStarts,
                                       const std::vector<StrResult>& strings,
                                       int cap = 800000,
                                       const std::function<bool()>& cancelled = {},
                                       std::atomic<uint32_t>* progress = nullptr);

// Build the directed call graph between discovered functions: sweep each function
// body once and emit a (from, to) edge for every direct CALL whose target is another
// discovered function. De-duplicated per caller. Pure (no UI); parallels the old
// BinaryViewTab::buildCallGraph, now run on the worker.
std::vector<CallEdgeR> BuildCallEdges(const BinaryFile& bin, IDisassembler& dis,
                                      const std::vector<FuncResult>& functions);

// Recognize known algorithms / crypto constants (AlgoScan) and map each constant hit to
// its referencing function. `xref` (from K_Xref) and `functions` (from K_Funcs) drive the
// extent mapping; pass a null xref / empty functions to skip it. Pure forward to
// ScanAlgorithms — kept here so the background worker invokes it like the other passes.
std::vector<AlgoMatch> ScanAlgorithmsJob(const BinaryFile& bin, const XrefIndex* xref,
                                         const std::vector<FuncResult>& functions);

// Decompile the function in [lo, hi) to structured pseudo-C off the UI thread (the
// K_Decompile pass). Mirrors BinaryViewTab::decompileFunctionText's pipeline (BuildCFG
// then Decompile). Base import/string resolution is always available; an optional
// immutable name snapshot adds user, discovered, and guessed names without sharing
// mutable UI state. `signature` supplies the inferred header and `x86` gates x86-only
// argument analysis. [lo,hi) is an exact exclusive interval and is never read past.
// Returns {"",{}} when it is empty/unmapped. lineVA backs pseudocode->assembly clicks.
DecompResult DecompileRegion(const BinaryFile& bin, IDisassembler& dis,
                             bool x86, uint64_t lo, uint64_t hi,
                             const DecompileNameMap* names = nullptr,
                             std::string_view signature = {});

} // namespace ds
