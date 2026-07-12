#include "XrefIndex.h"
#include "../Disasm/IDisassembler.h"
#include "../Tabs/DataRef.h"   // instrDataRef(): pure operand-string parse, no UI deps

#include <algorithm>

namespace ds {

void BuildXrefInto(XrefIndex& idx, const uint8_t* data, size_t size,
                   uint64_t base, IDisassembler& dis,
                   std::atomic<uint32_t>* progress) {
    if (!data || size == 0) return;
    Instruction in;
    size_t since = 0;   // bytes swept since the last progress publish
    for (size_t off = 0; off < size;) {
        uint64_t a = base + off;
        if (!dis.decodeOne(data + off, size - off, a, in) || in.length == 0) { ++off; ++since; continue; }
        // A relative branch/call records its target; a memory operand records the
        // data address it references (RIP-relative or absolute). Both map back to
        // this instruction as the referencing source.
        if (HasBranchTarget(in)) idx.toTarget[in.branchTarget].push_back(a);
        if (uint64_t ref = instrDataRef(in); ref && ref != in.branchTarget) {
            idx.toTarget[ref].push_back(a);
            idx.accessOf[a] = (uint8_t)instrDataAccess(in);   // Read / Write / Ref
        }
        off += in.length;
        since += in.length;
        if (progress && since >= 0x10000) { progress->fetch_add((uint32_t)since, std::memory_order_relaxed); since = 0; }
    }
    if (progress && since) progress->fetch_add((uint32_t)since, std::memory_order_relaxed);
}

void FinalizeXrefIndex(XrefIndex& idx) {
    for (auto& kv : idx.toTarget) {
        auto& v = kv.second;
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }
}

bool FindRefsInBuffer(const uint8_t* data, size_t size, uint64_t base, uint64_t target,
                      IDisassembler& dis, std::vector<uint64_t>& out, size_t cap) {
    if (!data || size == 0) return true;
    Instruction in;
    for (size_t off = 0; off < size;) {
        uint64_t a = base + off;
        if (!dis.decodeOne(data + off, size - off, a, in) || in.length == 0) { ++off; continue; }
        if (instrRefsAddr(in, target)) {
            out.push_back(a);
            if (out.size() >= cap) return false;   // hit the cap: stop
        }
        off += in.length;
    }
    return true;
}

} // namespace ds
