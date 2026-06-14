#pragma once
//
// XrefIndex.h
// Whole-program cross-reference index. A single linear decode sweep over the code
// records, for every referenced target address, the instruction addresses that
// reference it (via a branch/call target or a data memory operand). This turns the
// previously O(n)-per-query xref search (startXrefSearch) into an O(1) lookup, and
// powers the "Xrefs" panel's "who references this?" view.
//
// Pure logic (no ImGui / Win32) so it is unit-testable in the sandbox: feed a byte
// buffer + a stub IDisassembler and assert the target -> sources mapping.
//
#include <atomic>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace ds {

class IDisassembler;

struct XrefIndex {
    // target address -> instruction addresses that reference it (sorted, de-duped).
    std::unordered_map<uint64_t, std::vector<uint64_t>> toTarget;
    // source instruction -> how it accesses its DATA reference (XrefAccess from
    // Tabs/DataRef.h, stored as its uint8_t value to keep this header light):
    // 0 = Read, 1 = Write, 2 = Ref (address taken / lea). Only data refs are
    // recorded; branch/call edges aren't (their kind is implicit). Lets the
    // Xrefs panel group "Writers" vs "Readers" for a data address.
    std::unordered_map<uint64_t, uint8_t> accessOf;

    void clear() { toTarget.clear(); accessOf.clear(); }
    bool empty() const { return toTarget.empty(); }

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
void BuildXrefInto(XrefIndex& idx, const uint8_t* data, size_t size,
                   uint64_t base, IDisassembler& dis,
                   std::atomic<uint32_t>* progress = nullptr);
void FinalizeXrefIndex(XrefIndex& idx);

// Decode-sweep one region [data, data+size) (base = VA of data[0]) and append the
// address of every instruction that references `target` to `out`. Returns false (and
// stops) once `out` reaches `cap` — the caller uses that to stop scanning further
// regions. Used by the targeted "who references this address?" live xref search, run
// on the LiveScanService worker. Pure (no UI/Win32).
bool FindRefsInBuffer(const uint8_t* data, size_t size, uint64_t base, uint64_t target,
                      IDisassembler& dis, std::vector<uint64_t>& out, size_t cap = 3000);

} // namespace ds
