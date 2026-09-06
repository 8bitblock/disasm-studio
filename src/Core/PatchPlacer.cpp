//
// PatchPlacer.cpp — see PatchPlacer.h. Pure logic, no engine/OS deps.
//
#include "PatchPlacer.h"

#include <cstdint>

namespace ds {

static void PutRel32(std::vector<uint8_t>& out, int32_t rel) {
    out.push_back((uint8_t)(rel & 0xFF));
    out.push_back((uint8_t)((rel >> 8) & 0xFF));
    out.push_back((uint8_t)((rel >> 16) & 0xFF));
    out.push_back((uint8_t)((rel >> 24) & 0xFF));
}

bool MakeRel32Jmp(uint64_t siteVA, uint64_t targetVA, std::vector<uint8_t>& out) {
    const int64_t rel = (int64_t)targetVA - (int64_t)(siteVA + kDetourJmpLen);
    if (rel < INT32_MIN || rel > INT32_MAX) return false;
    out.clear();
    out.push_back(0xE9);
    PutRel32(out, (int32_t)rel);
    return true;
}

std::vector<CodeCave> FindCodeCaves(const std::vector<ExecRegion>& regions,
                                    size_t minLen,
                                    const std::vector<uint64_t>& avoid) {
    if (minLen == 0) minLen = 1;
    std::vector<CodeCave> caves;
    for (const auto& r : regions) {
        if (!r.data || r.size == 0) continue;
        size_t i = 0;
        while (i < r.size) {
            const uint8_t b = r.data[i];
            if (b != 0x00 && b != 0xCC) { ++i; continue; }
            size_t j = i + 1;
            while (j < r.size && r.data[j] == b) ++j;
            const size_t runLen = j - i;
            if (runLen >= minLen) {
                const uint64_t caveVA = r.va + i;
                bool blocked = false;
                for (uint64_t a : avoid)
                    if (a >= caveVA && a < caveVA + runLen) { blocked = true; break; }
                if (!blocked) caves.push_back({ caveVA, runLen });
            }
            i = j;
        }
    }
    return caves;
}

PlaceResult PlacePatch(const PlaceInput& in) {
    PlaceResult res;
    const size_t need = in.newBody.size();
    if (need == 0) { res.reason = "empty patch body"; return res; }   // Refused

    // 1) Body fits the original span -> overwrite in place + NOP-pad the remainder.
    if (in.origLen >= need) {
        PatchWrite w;
        w.va = in.siteVA;
        w.origLen = in.origLen;
        w.bytes = in.newBody;
        w.bytes.resize(in.origLen, in.nop);
        res.writes.push_back(std::move(w));
        res.status = PlaceStatus::InSpan;
        return res;
    }

    // 2) Detour required. The site must be able to host a 5-byte near JMP.
    if (in.origLen < kDetourJmpLen) {
        res.reason = "selection is " + std::to_string(in.origLen) +
                     " bytes; need >= " + std::to_string(kDetourJmpLen) +
                     " to write a JMP detour (select more instructions)";
        return res;   // Refused
    }

    const size_t caveNeed = need + kDetourJmpLen;   // body + JMP-back

    // Pick the destination: a caller-allocated region wins; else the first fitting cave.
    uint64_t caveVA = 0;
    bool haveCave = false;
    if (in.allocVAValid) {
        caveVA = in.allocVA;
        haveCave = true;
    } else {
        for (const auto& c : in.caves)
            if (c.size >= caveNeed) { caveVA = c.va; haveCave = true; break; }
    }

    if (!haveCave) {
        if (in.allowAlloc) {
            res.status = PlaceStatus::NeedsAlloc;
            res.requiredCaveSize = caveNeed;
            res.reason = "no code cave >= " + std::to_string(caveNeed) +
                         " bytes; allocate a region and re-plan with allocVA";
            return res;
        }
        res.reason = "no code cave large enough (need " + std::to_string(caveNeed) +
                     " bytes) and live allocation not permitted";
        return res;   // Refused
    }

    // 2a) Site: JMP to the cave, then NOP-pad out the rest of the replaced span.
    std::vector<uint8_t> jmpToCave;
    if (!MakeRel32Jmp(in.siteVA, caveVA, jmpToCave)) {
        res.reason = "cave is out of +/-2GB rel32 range from the patch site";
        return res;   // Refused
    }
    {
        PatchWrite site;
        site.va = in.siteVA;
        site.origLen = in.origLen;
        site.bytes = std::move(jmpToCave);
        site.bytes.resize(in.origLen, in.nop);
        res.writes.push_back(std::move(site));
    }

    // 2b) Cave: the body, then a JMP back to the instruction after the replaced span.
    const uint64_t returnVA  = in.siteVA + in.origLen;
    const uint64_t jmpBackVA = caveVA + need;   // the JMP-back sits right after the body
    std::vector<uint8_t> jmpBack;
    if (!MakeRel32Jmp(jmpBackVA, returnVA, jmpBack)) {
        res.reason = "return address is out of +/-2GB rel32 range from the cave";
        res.writes.clear();
        return res;   // Refused
    }
    {
        PatchWrite cave;
        cave.va = caveVA;
        cave.origLen = caveNeed;   // overwrites caveNeed filler bytes (revert restores them)
        cave.bytes = in.newBody;
        cave.bytes.insert(cave.bytes.end(), jmpBack.begin(), jmpBack.end());
        res.writes.push_back(std::move(cave));
    }

    res.status = PlaceStatus::Detour;
    res.caveVA = caveVA;
    res.caveVAValid = true;
    return res;
}

} // namespace ds
