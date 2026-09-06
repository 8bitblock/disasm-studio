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
#include "CodeDataClassifier.h"
#include "FunctionAnalyzer.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ds {

class BinaryFile;
class IDisassembler;
enum class Arch;
struct XrefIndex;
struct AlgoMatch;
struct PjDataOverride;

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
    bool        analystDefined = false;
    bool        noreturnValid = false;
    bool        noreturn = false;
    uint8_t     analystMode = 0; // 0 unspecified, 1 ARM, 2 Thumb
    std::string callingConvention;
    std::string prototype;
    std::vector<FunctionChunk> chunks;
    bool ownershipTruncated = false;
    FunctionSeedKind seedKind = FunctionSeedKind::Prologue;
    FunctionBoundaryConfidence boundaryConfidence = FunctionBoundaryConfidence::Heuristic;
};

// Optional non-instruction rows carried by the same clipper-friendly index as
// ordinary instruction/function/string rows. RegionHeader is the modeled PE
// header or one loader section; DataDirective is a bounded 1..16-byte `db` row;
// DataTruncated makes the byte cap explicit rather than silently omitting a tail.
enum class ListingRowType : uint8_t {
    Normal = 0,
    RegionHeader,
    DataDirective,
    DataTruncated,
    CodePage,       // fixed-size executable span; decoded only when visible/requested
    LocationLabel   // materialized UI-only loc_ target row
};
inline constexpr uint32_t kListingPeHeaderIndex = 0xFFFFFFFFu;
inline constexpr size_t   kDefaultListingDataByteCap = 4u * 1024u * 1024u;
inline constexpr size_t   kListingDataBytesPerRegion = 1u * 1024u * 1024u;
inline constexpr size_t   kListingCodePageBytes = 4u * 1024u;

// One row of the full-program listing index (parallels BinaryViewTab::ListRow).
// The original four fields intentionally stay first so existing aggregate
// initializers for instruction/divider/string rows remain source-compatible.
struct ListRowR {
    uint64_t       addr = 0;
    bool           divider = false;
    bool           strData = false;
    int            strIdx = -1;
    ListingRowType type = ListingRowType::Normal;
    uint32_t       sectionIndex = kListingPeHeaderIndex; // original BinaryFile::sections() index
    uint16_t       dataSize = 0;                         // DataDirective byte count
    bool           folded = false;                      // RegionHeader snapshot
    uint64_t       aux = 0;                             // region mapped size / omitted byte count
    CodeDataKind   dataKind = CodeDataKind::Data;       // typed executable-data directive
    uint8_t        dataWidth = 1;                       // directive element width (1/2/4/8)
    uint32_t       codeRegion = 0;                      // contiguous CodePage run identity
};

// Immutable listing-layout snapshot. Section identity is (RVA,name), never its
// vector index, so a persisted choice survives parser reordering. Defaults keep
// executable sections visible/unfolded and optional data sections hidden/folded.
struct ListingSectionState {
    uint64_t    rva = 0;
    std::string name;
    bool        visible = false;
    bool        folded = true;
};
struct ListingLayout {
    bool                             peHeaderVisible = false;
    bool                             peHeaderFolded = true;
    std::vector<ListingSectionState> sections;
};
struct ListingRegionPlan {
    uint32_t    sectionIndex = kListingPeHeaderIndex;
    bool        peHeader = false;
    bool        executable = false;
    bool        folded = false;
    std::string name;
    uint64_t    address = 0;
    uint64_t    mappedSize = 0;
    uint64_t    virtualSize = 0;
};

ListingLayout MakeDefaultListingLayout(const BinaryFile& bin);
void          ReconcileListingLayout(const BinaryFile& bin, ListingLayout& layout);
std::vector<ListingRegionPlan> PlanListingRegions(const BinaryFile& bin,
                                                   const ListingLayout* layout = nullptr);

// Code/data decisions are shared by the ordinary worker and Cortex. The digest
// excludes transient image generations and display-only evidence text.
uint64_t DigestCodeDataScope(const CodeDataMap* map);
std::shared_ptr<const CodeDataMap> ApplyCodeDataOverrides(
    const BinaryFile& bin, const std::vector<PjDataOverride>& overrides,
    std::shared_ptr<const CodeDataMap> input);
struct XrefCodeRange { uint64_t address = 0, size = 0; uint32_t sectionIndex = 0; };
struct XrefRangePlan {
    std::vector<XrefCodeRange> ranges;
    uint64_t decodeBytes = 0, classifiedDataBytes = 0, scopeDigest = 0;
    bool classificationApplied = false, classificationTruncated = false, cancelled = false;
};
// Covers every file-backed executable section regardless of listing visibility.
// Only positive data spans split decoding; adjacent code/unknown spans merge.
XrefRangePlan PlanXrefRanges(const BinaryFile& bin, const CodeDataMap* classification,
                              const std::function<bool()>& cancelled = {});

// One directed call edge between two discovered functions (caller -> callee). The
// UI folds these into its callees_/callers_ adjacency maps.
struct CallEdgeR { uint64_t from = 0, to = 0; };

struct AnalyzeOut {
    std::vector<FuncResult> functions;   // sorted by address (FunctionAnalyzer order)
    std::string             summary;
    CodeDataMap             codeData;    // complete executable-range partition
    bool                    codeDataValid = false;
};

// Immutable address->display-name snapshot supplied to an off-thread decompile.
// The UI builds this from discovered/guessed functions plus analyst renames, so
// the worker never reaches into mutable tab/project state.
using DecompileNameMap = std::unordered_map<uint64_t, std::string>;

// Shared completeness helpers for worker and render-thread/live decompilation.
// Warning insertion keeps text, legacy lineVA, and validity-bearing origins in
// lockstep by adding one explicitly synthetic source row.
void AddDecompileDiagnostic(DecompResult& result,
                            DecompileDiagnosticKind kind,
                            std::string message);
void PrependDecompileWarning(DecompResult& result);

// Extract ASCII/UTF-8 + UTF-16LE printable runs (>= 4 characters) from the file
// image, mapping offsets through offsetToVA. Returned sorted by address and capped.
// `truncated`, when non-null, reports that additional results existed past the cap.
// This is the FILE-mode scan; live/debuggee buffers use ScanStringsBuffer on the
// LiveScanService worker.
// `progress`, when non-null, is set to the number of image bytes scanned so far
// (a background worker publishes it for a progress bar; never read by this fn).
// `cancelled`, when supplied, is polled at bounded byte intervals in both encoding
// passes. A cancelled scan returns no partial result and does not report full
// progress, allowing an AnalysisService worker to yield promptly after an epoch
// change.
std::vector<StrResult> ScanStringsImage(const BinaryFile& bin,
                                        size_t cap = kDefaultStringScanCap,
                                        std::atomic<uint32_t>* progress = nullptr,
                                        bool* truncated = nullptr,
                                        const std::function<bool()>& cancelled = {});

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
// lookup can binary-search. This convenience form accepts only a structured image
// with a loader-authoritative machine; Raw/Unknown images must use an exact decoder
// overload below.
AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames);

// Exact decoder form used by AnalysisService. This matters for raw blobs: their
// bytes carry neither a machine nor byte-order/ISA-feature metadata, so every
// analyst-selected field must reach classification and recursive discovery.
AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames,
                                 const DecoderConfig& decoder,
                                 const std::function<bool()>& cancelled = {},
                                 const std::vector<uint64_t>& analystSeeds = {},
                                 const FunctionNoreturnDecisionResolver& noreturnDecision = {});

// Backward-compatible little-endian/default-feature shorthand. New production
// callers must use DecoderConfig so Raw byte order and RVC/microMIPS cannot be
// silently discarded.
AnalyzeOut AnalyzeFunctionsNamed(const BinaryFile& bin, IDisassembler& dis,
                                 const std::vector<StrResult>& strings, bool guessNames,
                                 Arch arch,
                                 const std::function<bool()>& cancelled = {},
                                 const std::vector<uint64_t>& analystSeeds = {},
                                 const FunctionNoreturnDecisionResolver& noreturnDecision = {});

// Build the virtual listing descriptor index from an immutable layout snapshot.
// Visible regions receive a RegionHeader row. Each unfolded executable section is
// represented by fixed-size CodePage descriptors; this function performs ZERO
// instruction decoding. The UI decodes only visible/on-demand pages. Unfolded data
// sections / the PE header retain bounded 16-byte directives and exact string rows.
// `strings` must be sorted by address; strIdx indexes into it. `progress`, when
// non-null, reports mapped bytes described (not decoded instructions).
std::vector<ListRowR> BuildListingRows(const BinaryFile& bin,
                                       const std::vector<StrResult>& strings,
                                       const std::function<bool()>& cancelled = {},
                                       std::atomic<uint32_t>* progress = nullptr,
                                       const ListingLayout* layout = nullptr,
                                       size_t maxDataBytes = kDefaultListingDataByteCap,
                                       const CodeDataMap* codeData = nullptr);

// Normalize lazy code descriptors around authoritative instruction roots. Adjacent,
// byte-contiguous CodePages from the same codeRegion are first treated as one run;
// each root inside that run then starts an independent subrun, and every subrun is
// repaginated from its own start. This is deliberately separate from prefixSkip:
// a page prefix describes bytes owned by one crossing instruction, while an
// interior function/entry root must not make all preceding bytes disappear.
// Non-code rows retain their original order and contents. Every emitted code
// subrun receives a distinct non-zero codeRegion.
std::vector<ListRowR> NormalizeListingCodePagesAtRoots(
    const std::vector<ListRowR>& rows,
    const std::vector<uint64_t>& authoritativeRoots);

// Return the largest suffix length in [0, requested] accepted by `readable`.
// Readability of [target-N,target) is monotone with N, so a failed full
// lookback can be narrowed in logarithmic probes instead of discarding useful
// context at a mapped-section or process-page boundary. On a nonzero result the
// accepted length is probed once more, allowing a caller's predicate to leave
// the corresponding bytes in its scratch buffer.
size_t LongestReadableLookback(size_t requested,
                               const std::function<bool(size_t)>& readable);

// Decode a bounded stream from `from` and report whether instruction boundaries
// land exactly on `target`. Malformed bytes advance by invalidDecodeWidth(), the
// same recovery contract used by the listing's emitted `db` rows, so alignment
// cannot invent a navigation wall at undecodable data.
bool ListingDecodeReaches(const uint8_t* bytes, size_t available,
                          uint64_t from, uint64_t target,
                          IDisassembler& dis, size_t maxSteps = 256);

// Bounded primitive used by Binary View to materialize one CodePage. `available`
// may include lookahead bytes beyond `pageBytes`; instructions whose start belongs
// to this page are retained even when they end in the next page. `prefixSkip`
// suppresses bytes already owned by the preceding page's crossing instruction and
// `nextPrefixSkip` propagates the continuation checkpoint forward.
struct DecodedListingPage {
    std::vector<Instruction> instructions;
    uint32_t nextPrefixSkip = 0;
};
DecodedListingPage DecodeListingCodePage(const uint8_t* bytes, size_t available,
                                         uint64_t address, size_t pageBytes,
                                         uint32_t prefixSkip, size_t lookaheadBytes,
                                         IDisassembler& dis);

// Exact boundary predicate shared by lazy navigation/trace planning. A mapped
// byte is not a safe software-breakpoint site merely because it belongs to a
// CodePage; it must equal the start of an instruction decoded for that page.
bool ListingInstructionsHaveStart(const std::vector<Instruction>& instructions, uint64_t address);

// A document/image-generation identity deliberately excludes byte revisions:
// a patch at an unrelated address must not retire an analyst's selection. The
// entire decoder configuration is part of the identity, including byte order
// and ISA features. Image replacement and decoder changes retire old records.
struct ListingInstructionScope {
    uint64_t documentId = 0;
    uint64_t imageId = 0;
    DecoderConfig decoder;

    bool operator==(const ListingInstructionScope&) const = default;
};

inline constexpr size_t kListingInstructionSnapshotByteCap = 64u * 1024u;
inline constexpr size_t kListingInstructionRecordCap = 65536;
inline constexpr size_t kListingInstructionRetainedByteCap = 16u * 1024u * 1024u;

// An owned displayed instruction, independent of the page LRU. Raw bytes are
// the authority input; Instruction::bytes is presentation only. Callers still
// validate executable mapping and current code/data classification, then decode
// exactly this start and call matches() before performing an action. Keeping a
// snapshot never proves surrounding instruction boundaries or trace sites.
struct ListingInstructionSnapshot {
    ListingInstructionScope scope;
    Instruction instruction;
    std::vector<uint8_t> bytes;

    static bool IsInstruction(const Instruction& in) {
        return in.length != 0 && in.length <= kListingInstructionSnapshotByteCap &&
               in.length - 1 <= (std::numeric_limits<uint64_t>::max)() - in.address &&
               !in.mnemonic.empty() && in.mnemonic != "db" && in.mnemonic != "dw" &&
               in.mnemonic != "dd" && in.mnemonic != "dq";
    }

    static ListingInstructionSnapshot Capture(const ListingInstructionScope& owner,
                                               const Instruction& displayed,
                                               const uint8_t* raw, size_t available) {
        if (!IsInstruction(displayed) || !raw || available < displayed.length)
            return {};
        ListingInstructionSnapshot result;
        result.scope = owner;
        result.instruction = displayed;
        result.bytes.assign(raw, raw + displayed.length);
        return result;
    }

    bool valid() const {
        return IsInstruction(instruction) && bytes.size() == instruction.length;
    }

    bool matches(const ListingInstructionScope& owner, const Instruction& decoded,
                 const uint8_t* raw, size_t available) const {
        return valid() && scope == owner && IsInstruction(decoded) &&
               decoded.address == instruction.address &&
               decoded.length == instruction.length && raw &&
               available >= bytes.size() && std::equal(bytes.begin(), bytes.end(), raw);
    }

    bool overlaps(uint64_t address, uint64_t byteCount) const {
        if (!valid() || byteCount == 0) return false;
        // Subtract starts instead of adding exclusive ends so VA 0 and the
        // last representable byte both work, even for a hostile changed span.
        return instruction.address <= address
            ? address - instruction.address < instruction.length
            : instruction.address - address < byteCount;
    }
};

// Per-image UI authority for an explicit mutation at a displayed provisional
// instruction start. Decoder proof remains a separate input: accepting one row
// never promotes its page, nearby rows, or trace seeds. `displayedInstruction`
// prevents keyboard actions on data/string rows from manufacturing code.
class ListingBoundaryAuthority {
public:
    bool actionable(uint64_t address, bool decoderProven) const {
        return decoderProven || analyst_.count(address) != 0;
    }
    bool analystAccepted(uint64_t address) const {
        return analyst_.count(address) != 0;
    }
    bool acceptDisplayed(uint64_t address, bool displayedInstruction) {
        if (!displayedInstruction || analyst_.size() >= kListingInstructionRecordCap)
            return false;
        // Compatibility for address-only callers. Production mutations retain
        // a validated snapshot using the overload below.
        const bool added = analyst_.try_emplace(address).second;
        if (added) ++revision_;
        return added;
    }
    bool acceptDisplayed(const ListingInstructionSnapshot& snapshot) {
        if (!snapshot.valid()) return false;
        const uint64_t address = snapshot.instruction.address;
        auto old = analyst_.find(address);
        if (old != analyst_.end() && old->second.matches(snapshot.scope,
                snapshot.instruction, snapshot.bytes.data(), snapshot.bytes.size()))
            return false;
        if (old == analyst_.end() && analyst_.size() >= kListingInstructionRecordCap)
            return false;
        const size_t replacedBytes = old == analyst_.end() ? 0 : old->second.bytes.size();
        if (snapshot.bytes.size() > kListingInstructionRetainedByteCap -
                                    (retainedBytes_ - replacedBytes))
            return false;
        analyst_.insert_or_assign(address, snapshot);
        retainedBytes_ = retainedBytes_ - replacedBytes + snapshot.bytes.size();
        ++revision_;
        return true;
    }
    const ListingInstructionSnapshot* acceptedSnapshot(uint64_t address) const {
        const auto found = analyst_.find(address);
        return found != analyst_.end() && found->second.valid() ? &found->second : nullptr;
    }
    bool erase(uint64_t address) {
        const auto found = analyst_.find(address);
        if (found == analyst_.end()) return false;
        retainedBytes_ -= found->second.bytes.size();
        analyst_.erase(found);
        ++revision_;
        return true;
    }
    // A whole-image patch-set reconstruction may change disjoint byte spans.
    // Let the owner compare each immutable record with its current mapped bytes
    // and retire only changed records, without rebuilding decoder/page proof.
    // The predicate must not mutate this authority while it is being visited.
    template<class Predicate>
    size_t eraseIf(Predicate&& predicate) {
        size_t removed = 0;
        for (auto it = analyst_.begin(); it != analyst_.end();) {
            if (predicate(static_cast<const ListingInstructionSnapshot&>(it->second))) {
                retainedBytes_ -= it->second.bytes.size();
                it = analyst_.erase(it);
                if (removed == 0) ++revision_;
                ++removed;
            } else {
                ++it;
            }
        }
        return removed;
    }
    size_t invalidateOverlapping(uint64_t address, uint64_t byteCount) {
        if (byteCount == 0) return 0;
        size_t removed = 0;
        for (auto it = analyst_.begin(); it != analyst_.end();) {
            const bool overlaps = it->second.valid()
                ? it->second.overlaps(address, byteCount)
                : it->first >= address && it->first - address < byteCount;
            if (overlaps) {
                retainedBytes_ -= it->second.bytes.size();
                it = analyst_.erase(it);
                ++removed;
            } else {
                ++it;
            }
        }
        if (removed) ++revision_;
        return removed;
    }
    void clear() {
        if (analyst_.empty()) return;
        analyst_.clear();
        retainedBytes_ = 0;
        ++revision_;
    }
    size_t size() const { return analyst_.size(); }
    size_t retainedBytes() const { return retainedBytes_; }
    uint64_t revision() const { return revision_; }

private:
    std::unordered_map<uint64_t, ListingInstructionSnapshot> analyst_;
    size_t retainedBytes_ = 0;
    uint64_t revision_ = 0;
};

struct ListingPrefixCheckpoint {
    uint64_t address = 0;   // CodePage start
    uint32_t prefixSkip = 0;
};
struct ListingPrefixResult {
    bool complete = false;
    uint64_t bytesScanned = 0;
    std::vector<ListingPrefixCheckpoint> checkpoints;
};

// Exact checkpoint preparation is deliberately capped. A random jump hundreds
// of megabytes into a variable-width stream must never trigger a linear decode
// from the section front merely to paint the viewport.
constexpr uint64_t kListingPrefixExactByteCap = 64ull * 1024ull;

// A far page can still be shown immediately. For x86-family streams, inspect at
// most the architectural 15-byte instruction window before the page and vote
// across every locally plausible decode path. This is an honest estimate (never
// breakpoint authority); the counters make the constant-work contract testable.
struct ListingPrefixEstimate {
    uint32_t prefixSkip = 0;
    uint32_t decodeCalls = 0;
    uint32_t candidates = 0;
    uint32_t bytesExamined = 0;
};
bool   ListingArchNeedsPagePrefix(Arch arch);
size_t ListingArchMaxInstructionBytes(Arch arch);
size_t ListingArchInstructionAlignment(Arch arch);
ListingPrefixEstimate EstimateListingPagePrefix(
    const uint8_t* bytes, size_t available, uint64_t windowAddress,
    uint64_t pageAddress, size_t maxInstructionBytes, IDisassembler& dis,
    size_t candidateAlignment = 1);

// Starting at a trustworthy section/function instruction boundary, derive exact
// continuation checkpoints through `targetPage`. This is designed for an on-demand
// background job: it is cancellable, reports byte progress, and records every 4 KiB
// page boundary crossed. Requests beyond kListingPrefixExactByteCap fail before
// decoding; callers should use EstimateListingPagePrefix for immediate far views.
ListingPrefixResult BuildListingPrefixCheckpoints(
    const uint8_t* bytes, size_t available, uint64_t startAddress,
    uint64_t sectionPageBase, uint64_t targetPage, size_t lookaheadBytes,
    IDisassembler& dis, const std::function<bool()>& cancelled = {},
    std::atomic<uint32_t>* progress = nullptr);

// Build the directed call graph between discovered functions: sweep each function
// body once and emit a (from, to) edge for every direct CALL whose target is another
// discovered function. De-duplicated per caller. Pure (no UI); parallels the old
// BinaryViewTab::buildCallGraph, now run on the worker.
std::vector<CallEdgeR> BuildCallEdges(const BinaryFile& bin, IDisassembler& dis,
                                      const std::vector<FuncResult>& functions,
                                      const JumpTableResolver& resolveTable = {},
                                      const NoreturnCallResolver& resolveNoreturnCall = {},
                                      const DirectTargetResolver& resolveDirectTarget = {},
                                      const std::function<bool()>& cancelled = {});

// Recognize known algorithms / crypto constants (AlgoScan) and map each constant hit to
// its referencing function. `xref` (from K_Xref) and `functions` (from K_Funcs) drive the
// extent mapping; pass a null xref / empty functions to skip it. Pure forward to
// ScanAlgorithms — kept here so the background worker invokes it like the other passes.
std::vector<AlgoMatch> ScanAlgorithmsJob(const BinaryFile& bin, const XrefIndex* xref,
                                         const std::vector<FuncResult>& functions,
                                         const std::function<bool()>& cancelled = {});

// Decompile the function in [lo, hi) to structured pseudo-C off the UI thread (the
// K_Decompile pass). Mirrors BinaryViewTab::decompileFunctionText's pipeline (BuildCFG
// then Decompile). Base import/string resolution is always available; an optional
// immutable name snapshot adds user, discovered, and guessed names without sharing
// mutable UI state. `signature` supplies the inferred header. The exact decoder
// descriptor is mandatory so x86-32 can never silently enter the x64 ABI model.
// [lo,hi) is an exact exclusive interval and is never read past.
// Production entry point: exact decoder target/byte order, format-derived ABI,
// and optional noncontiguous ownership chunks. Raw images use Unknown unless a
// recognized analyst calling-convention override supplies the ABI.
DecompileTarget DecompileTargetForBinary(const BinaryFile& bin, Arch arch,
                                         std::string_view analystCallingConvention = {});
DecompResult DecompileRegion(const BinaryFile& bin, IDisassembler& dis,
                             const DecoderConfig& decoder,
                             uint64_t lo, uint64_t hi,
                             const DecompileNameMap* names = nullptr,
                             std::string_view signature = {},
                             const NoreturnCallResolver& isNoreturnCall = {},
                             const std::vector<FunctionChunk>* chunks = nullptr,
                             bool ownershipTruncated = false,
                             std::string_view analystCallingConvention = {});

} // namespace ds
