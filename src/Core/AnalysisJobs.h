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
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;
class IDisassembler;
struct XrefIndex;
struct AlgoMatch;

// One extracted printable string (parallels BinaryViewTab::Strng).
struct StrResult { uint64_t address = 0; std::string text; bool wide = false; };

// One discovered + optionally heuristically-named function
// (parallels BinaryViewTab::Func plus its guessReason_ entry).
struct FuncResult {
    uint64_t    address = 0;
    uint32_t    size    = 0;
    std::string name;
    bool        guessed = false;
    std::string reason;   // basis for a guessed name (tooltip); "" when not guessed
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

// Extract ASCII/UTF-8 + UTF-16LE printable runs (>= 4 chars) from the file image,
// mapping offsets through offsetToVA. Returned sorted by address, capped at `cap`.
// This is the FILE-mode scan only; the live/debuggee scan stays on the UI thread.
// `progress`, when non-null, is set to the number of image bytes scanned so far
// (a background worker publishes it for a progress bar; never read by this fn).
std::vector<StrResult> ScanStringsImage(const BinaryFile& bin, size_t cap = 20000,
                                        std::atomic<uint32_t>* progress = nullptr);

// Append ASCII/UTF-8 + UTF-16LE printable runs (>= 4 chars) found in the raw buffer
// [d, d+n) to `out`, mapping a buffer offset k to the virtual address (base + k).
// Stops once `out` reaches `cap`. This is the buffer primitive behind the live
// (debuggee-memory) string scan, run on the LiveScanService worker. The caller
// sorts/de-dups across buffers. Pure (no UI/Win32).
void ScanStringsBuffer(const uint8_t* d, size_t n, uint64_t base,
                       std::vector<StrResult>& out, size_t cap = 20000);

// Discover functions (FunctionAnalyzer) and, when `guessNames`, apply the heuristic
// namer (FunctionNamer) using the binary's imports + the provided strings. `strings`
// must be sorted by address (as ScanStringsImage returns) so the string-reference
// lookup can binary-search.
AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames);

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

} // namespace ds
