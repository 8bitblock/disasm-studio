#pragma once
//
// XrefIndex.h
// Whole-program cross-reference index. A single linear decode sweep over the code
// records, for every referenced target address, the instruction addresses that
// reference it (via a branch/call target, a data memory operand, or a conservatively
// admitted immediate pointer). This turns the previously O(n)-per-query xref search
// (startXrefSearch) into an O(1) lookup, and powers the "Xrefs" panel's "who
// references this?" view.
//
// Pure logic (no ImGui / Win32) so it is unit-testable in the sandbox: feed a byte
// buffer + a stub IDisassembler and assert the target -> sources mapping.
//
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <unordered_map>
#include <vector>

namespace ds {

class IDisassembler;
struct Instruction;

// Optional image-aware control-flow target resolution. Static-image callers use
// this for targets not fully represented by the decoder alone (notably x86-16
// segment:offset firmware aliases). Live callers can omit it and retain the
// decoder-only behavior.
using XrefTargetResolver = std::function<bool(const Instruction&, uint64_t&)>;

// Whole-image xref discovery consumes attacker-controlled decode input and may
// otherwise grow one hash node/vector per instruction. These defaults bound CPU
// and retained memory while remaining large enough for ordinary application
// images. Callers may tighten them for targeted work, but should not remove the
// bounds from an automatic analysis path.
inline constexpr uint64_t kDefaultXrefByteBudget = 256ull * 1024ull * 1024ull;
inline constexpr uint64_t kDefaultXrefDecodeBudget = 32ull * 1024ull * 1024ull;
inline constexpr size_t   kDefaultXrefEdgeBudget = 4ull * 1024ull * 1024ull;
inline constexpr size_t   kDefaultXrefTargetBudget = 512ull * 1024ull;

enum class XrefStopReason : uint8_t {
    None = 0,
    Cancelled,
    ByteBudget,
    DecodeBudget,
    EdgeBudget,
    TargetBudget,
    AddressSpaceLimit,
};

const char* XrefStopReasonText(XrefStopReason reason);

struct XrefBuildLimits {
    uint64_t maxBytes = kDefaultXrefByteBudget;
    uint64_t maxDecodeAttempts = kDefaultXrefDecodeBudget;
    size_t   maxEdges = kDefaultXrefEdgeBudget;
    size_t   maxTargets = kDefaultXrefTargetBudget;
    // Cancellation is checked at the start of each region and after this many
    // swept bytes. A value of zero requests a check on every decode attempt.
    uint64_t cancellationCheckBytes = 4096;
    std::function<bool()> cancelled;
    // Immediate operands are only pointer candidates: `mov eax, 0` and large
    // scalar constants must not automatically become whole-image xrefs. Static
    // image callers provide a mapped-address predicate; an empty predicate
    // disables immediate-pointer indexing so callers without mapping authority
    // retain the historical behavior. Bare immediate zero is always rejected
    // as ambiguous scalar/null data; real VA-zero references remain available
    // through explicit memory operands and direct control-flow targets.
    std::function<bool(uint64_t)> immediateTargetMapped;
};

struct XrefIndex {
    // target address -> instruction addresses that reference it (sorted, de-duped).
    std::unordered_map<uint64_t, std::vector<uint64_t>> toTarget;
    // source instruction -> how it accesses its DATA reference (XrefAccess from
    // Tabs/DataRef.h, stored as its uint8_t value to keep this header light):
    // 0 = Read, 1 = Write, 2 = Ref (address taken / lea). Only data refs are
    // recorded; branch/call edges aren't (their kind is implicit). Lets the
    // Xrefs panel group "Writers" vs "Readers" for a data address.
    std::unordered_map<uint64_t, uint8_t> accessOf;

    // The static worker records the exact classification scope it inspected.
    // Live/raw-buffer callers leave classificationApplied false.
    bool classificationApplied = false;
    bool classificationTruncated = false;
    uint64_t classificationScopeDigest = 0;
    uint64_t classificationDataBytes = 0;

    // Completeness is part of the result contract: a partial bounded index must
    // never be mistaken for proof that an address has no references.
    bool           complete = true;
    XrefStopReason stopReason = XrefStopReason::None;
    uint64_t       bytesSwept = 0;
    uint64_t       decodeAttempts = 0;
    uint64_t       acceptedEdges = 0; // pre-finalize insertions; enforces memory budget

    void clear() {
        toTarget.clear();
        accessOf.clear();
        complete = true;
        stopReason = XrefStopReason::None;
        bytesSwept = 0;
        decodeAttempts = 0;
        acceptedEdges = 0;
        classificationApplied = classificationTruncated = false;
        classificationScopeDigest = classificationDataBytes = 0;
    }
    bool empty() const { return toTarget.empty(); }
    const char* incompleteReason() const {
        return complete ? "" : XrefStopReasonText(stopReason);
    }

    // Access kind for a source instruction's data ref (defaults to Read).
    uint8_t access(uint64_t src) const {
        auto it = accessOf.find(src);
        return it == accessOf.end() ? 0 : it->second;
    }

    // Sources referencing `target`, or nullptr if none.
    const std::vector<uint64_t>* sources(uint64_t target) const {
        auto it = toTarget.find(target);
        return it == toTarget.end() ? nullptr : &it->second;
    }

    // Total number of (source -> target) edges recorded.
    size_t edgeCount() const {
        size_t n = 0;
        for (const auto& kv : toTarget) n += kv.second.size();
        return n;
    }
};

// Sweep one code region [base, base+size) with dis.decodeOne and accumulate edges
// into `idx`. Call once per executable section / memory region. Finalize() sorts and
// de-dups each source list once all regions are added. `progress`, when non-null, is
// fetch-added with the bytes swept (accumulates across regions for a progress bar).
// Limits and counters are cumulative across calls so one index can safely cover
// many executable sections. Returns false when cancellation or a bound makes the
// result incomplete; the reason remains available on XrefIndex.
bool BuildXrefInto(XrefIndex& idx, const uint8_t* data, size_t size,
                   uint64_t base, IDisassembler& dis,
                   std::atomic<uint32_t>* progress = nullptr,
                   const XrefTargetResolver& resolveTarget = {},
                   const XrefBuildLimits& limits = {});
void FinalizeXrefIndex(XrefIndex& idx);

// Decode-sweep one region [data, data+size) (base = VA of data[0]) and append the
// address of every instruction that references `target` to `out`. Returns false (and
// stops) once `out` reaches `cap` — the caller uses that to stop scanning further
// regions. Used by the targeted "who references this address?" live xref search, run
// on the LiveScanService worker. Pure (no UI/Win32).
bool FindRefsInBuffer(const uint8_t* data, size_t size, uint64_t base, uint64_t target,
                      IDisassembler& dis, std::vector<uint64_t>& out, size_t cap = 3000,
                      const XrefTargetResolver& resolveTarget = {});

} // namespace ds
