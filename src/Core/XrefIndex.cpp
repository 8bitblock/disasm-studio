#include "XrefIndex.h"
#include "AddressSpan.h"
#include "../Disasm/IDisassembler.h"
#include "InstructionReference.h"   // TryGetInstrDataRef(): pure operand parse, VA 0 is valid

#include <algorithm>

namespace ds {

const char* XrefStopReasonText(XrefStopReason reason) {
    switch (reason) {
        case XrefStopReason::None:              return "";
        case XrefStopReason::Cancelled:         return "cancelled";
        case XrefStopReason::ByteBudget:        return "byte-scan budget reached";
        case XrefStopReason::DecodeBudget:      return "decode-attempt budget reached";
        case XrefStopReason::EdgeBudget:        return "xref edge budget reached";
        case XrefStopReason::TargetBudget:      return "xref target budget reached";
        case XrefStopReason::AddressSpaceLimit: return "address range exceeds 64-bit VA space";
    }
    return "xref scan incomplete";
}

bool BuildXrefInto(XrefIndex& idx, const uint8_t* data, size_t size,
                   uint64_t base, IDisassembler& dis,
                   std::atomic<uint32_t>* progress,
                   const XrefTargetResolver& resolveTarget,
                   const XrefBuildLimits& limits) {
    if (!idx.complete) return false;
    if (!data || size == 0) return true;
    const size_t requestedSize = size;
    size = ClampAddressableBytes(base, size);
    const bool addressClamped = size != requestedSize;
    Instruction in;
    size_t since = 0;   // bytes swept since the last progress publish
    uint64_t sinceCancellationCheck = limits.cancellationCheckBytes;
    auto publishProgress = [&] {
        if (!progress || !since) return;
        progress->fetch_add(static_cast<uint32_t>(since), std::memory_order_relaxed);
        since = 0;
    };
    auto stop = [&](XrefStopReason reason) {
        if (idx.complete) {
            idx.complete = false;
            idx.stopReason = reason;
        }
        publishProgress();
        return false;
    };
    auto shouldCancel = [&] {
        if (!limits.cancelled) return false;
        if (limits.cancellationCheckBytes != 0 &&
            sinceCancellationCheck < limits.cancellationCheckBytes)
            return false;
        sinceCancellationCheck = 0;
        return limits.cancelled();
    };
    auto accountBytes = [&](size_t count) {
        idx.bytesSwept += static_cast<uint64_t>(count);
        since += count;
        sinceCancellationCheck += static_cast<uint64_t>(count);
        if (progress && since >= 0x10000) publishProgress();
    };
    auto recordEdge = [&](uint64_t target, uint64_t source, bool dataReference,
                          uint8_t access) {
        if (idx.acceptedEdges >= static_cast<uint64_t>(limits.maxEdges))
            return stop(XrefStopReason::EdgeBudget);
        auto found = idx.toTarget.find(target);
        if (found == idx.toTarget.end()) {
            if (idx.toTarget.size() >= limits.maxTargets)
                return stop(XrefStopReason::TargetBudget);
            found = idx.toTarget.try_emplace(target).first;
        }
        found->second.push_back(source);
        ++idx.acceptedEdges;
        if (dataReference) idx.accessOf[source] = access;
        return true;
    };

    for (size_t off = 0; off < size;) {
        if (shouldCancel()) return stop(XrefStopReason::Cancelled);
        if (idx.bytesSwept >= limits.maxBytes)
            return stop(XrefStopReason::ByteBudget);
        if (idx.decodeAttempts >= limits.maxDecodeAttempts)
            return stop(XrefStopReason::DecodeBudget);
        uint64_t a = 0;
        if (!CheckedAddressAdd(base, static_cast<uint64_t>(off), a))
            return stop(XrefStopReason::AddressSpaceLimit);
        const uint64_t byteBudgetLeft = limits.maxBytes - idx.bytesSwept;
        const size_t decodeBytes = static_cast<size_t>(std::min<uint64_t>(
            static_cast<uint64_t>(size - off), byteBudgetLeft));
        if (!decodeBytes) return stop(XrefStopReason::ByteBudget);
        ++idx.decodeAttempts;
        if (!dis.decodeOne(data + off, decodeBytes, a, in) || in.length == 0 ||
            in.length > decodeBytes) {
            // Preserve the decoder's natural recovery alignment. Byte-wise
            // recovery after one malformed A32/A64 word or Thumb halfword
            // shifts the entire remaining sweep and poisons/misses xrefs.
            const size_t step = std::min<size_t>(
                decodeBytes, std::max<uint32_t>(1, dis.invalidDecodeWidth()));
            off += step;
            accountBytes(step);
            continue;
        }
        // A relative branch/call records its target; a memory operand records the
        // data address it references (RIP-relative or absolute). Both map back to
        // this instruction as the referencing source.
        uint64_t directTarget = 0;
        const bool directTargetValid = resolveTarget
                                     ? resolveTarget(in, directTarget)
                                     : TryGetDirectTarget(in, directTarget);
        if (directTargetValid && !recordEdge(directTarget, a, false, 0)) return false;
        uint64_t ref = 0;
        const bool dataRefValid = TryGetInstrDataRef(in, ref);
        if (dataRefValid && (!directTargetValid || ref != directTarget)) {
            if (!recordEdge(ref, a, true, static_cast<uint8_t>(instrDataAccess(in))))
                return false;
        }
        // x86-32 crackmes commonly materialize string/endpoint pointers with
        // `push offset ...` or `mov reg, offset ...`. The targeted xref search
        // already recognizes these through instrRefsAddr(); retain the same
        // edges in the precomputed index so triage can recover their owner.
        // TryGetInstrImmRef is deliberately narrow (mov/movabs/push and no
        // memory operand), while image-backed callers additionally reject
        // candidates that do not map into the current image.
        uint64_t immediateRef = 0;
        if (TryGetInstrImmRef(in, immediateRef) &&
            // A bare immediate zero is overwhelmingly a scalar/null sentinel,
            // especially in raw images mapped at VA zero. Unlike an explicit
            // memory operand or direct control-flow edge, it carries no shape
            // evidence that it denotes address 0, so suppress it rather than
            // manufacture thousands of false xrefs.
            immediateRef != 0 &&
            limits.immediateTargetMapped &&
            limits.immediateTargetMapped(immediateRef) &&
            (!directTargetValid || immediateRef != directTarget) &&
            (!dataRefValid || immediateRef != ref)) {
            if (!recordEdge(immediateRef, a, true,
                            static_cast<uint8_t>(XrefAccess::Ref)))
                return false;
        }
        off += in.length;
        accountBytes(in.length);
    }
    publishProgress();
    if (addressClamped) return stop(XrefStopReason::AddressSpaceLimit);
    return true;
}

void FinalizeXrefIndex(XrefIndex& idx) {
    for (auto& kv : idx.toTarget) {
        auto& v = kv.second;
        std::sort(v.begin(), v.end());
        v.erase(std::unique(v.begin(), v.end()), v.end());
    }
}

bool FindRefsInBuffer(const uint8_t* data, size_t size, uint64_t base, uint64_t target,
                      IDisassembler& dis, std::vector<uint64_t>& out, size_t cap,
                      const XrefTargetResolver& resolveTarget) {
    if (!data || size == 0) return true;
    size = ClampAddressableBytes(base, size);
    Instruction in;
    for (size_t off = 0; off < size;) {
        uint64_t a = 0;
        if (!CheckedAddressAdd(base, static_cast<uint64_t>(off), a)) break;
        if (!dis.decodeOne(data + off, size - off, a, in) || in.length == 0 ||
            in.length > size - off) {
            const size_t step = std::min<size_t>(
                size - off, std::max<uint32_t>(1, dis.invalidDecodeWidth()));
            off += step;
            continue;
        }
        uint64_t directTarget = 0;
        const bool resolvedControlFlow = resolveTarget &&
            resolveTarget(in, directTarget) && directTarget == target;
        if (resolvedControlFlow || instrRefsAddr(in, target)) {
            out.push_back(a);
            if (out.size() >= cap) return false;   // hit the cap: stop
        }
        off += in.length;
    }
    return true;
}

} // namespace ds
