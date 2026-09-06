#pragma once
//
// PatchPlacer.h
// Pure placement logic for hot-patches (feature F2). Given a compiled,
// position-independent patch body and the original instruction span the user is
// REPLACING, decide how to land it and emit the concrete byte writes the caller
// applies through BinaryViewTab::applyPatchBytes (so revert + persistence +
// File > Save Binary As keep working unchanged):
//
//   * InSpan    - the body fits in the original span: overwrite + NOP-pad.
//   * Detour    - the body is larger: overwrite the span with a near JMP to a code
//                 cave (or a caller-allocated region) holding the body + a JMP back.
//   * NeedsAlloc- no cave fits and the caller permitted live allocation: it should
//                 VirtualAllocEx `requiredCaveSize` bytes, then re-plan with
//                 allocVA + allocVAValid.
//   * Refused   - the span is too small to host a 5-byte JMP, or no space is available,
//                 or the cave is out of +/-2GB rel32 range. Reason is human-readable.
//
// "Replace the selection" semantics: the selected instructions are discarded (the
// user's new code supersedes them), so there is NO displaced-instruction relocation
// hazard. Hook-style insertion that preserves+relocates the original is a documented
// future extension, not implemented here.
//
// The patch body MUST be position-independent (RIP-relative; imports resolved via the
// IAT as indirect calls) so the same bytes are valid whether they run in-span or in a
// cave whose address is only chosen here. PatchCompiler is responsible for refusing
// code that needs an absolute relocation.
//
// No BinaryFile / ImGui / Win32 deps, so it is unit-testable with `cl` (see
// tests/patchplacer_test.cpp). A thin BinaryFile adapter builds the ExecRegion list.
//
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

// A slice of the loaded image to scan for code caves.
struct ExecRegion {
    uint64_t       va   = 0;       // virtual address of the region start
    const uint8_t* data = nullptr; // region bytes (borrowed; not owned)
    size_t         size = 0;
};

// A run of filler bytes usable to host detoured code.
struct CodeCave { uint64_t va = 0; size_t size = 0; };

// One concrete write the caller applies via applyPatchBytes(va, bytes, origLen, ...).
struct PatchWrite {
    uint64_t             va = 0;
    std::vector<uint8_t> bytes;       // bytes to write at va
    size_t               origLen = 0; // original span this overwrites (for revert capture)
};

enum class PlaceStatus { InSpan, Detour, NeedsAlloc, Refused };

struct PlaceResult {
    PlaceStatus             status = PlaceStatus::Refused;
    std::vector<PatchWrite> writes;               // apply in order via applyPatchBytes
    uint64_t                caveVA = 0;           // where the body landed (Detour)
    bool                    caveVAValid = false;  // Detour may legitimately land at VA 0
    size_t                  requiredCaveSize = 0; // NeedsAlloc: bytes the caller must allocate
    std::string             reason;               // human-readable, esp. when Refused/NeedsAlloc
};

// Near-JMP length (E9 rel32) — the smallest span a detour can overwrite.
inline constexpr size_t kDetourJmpLen = 5;

// Filler-byte run finder. Scans each region for >= `minLen` consecutive 0x00 or 0xCC
// bytes (the usual alignment padding between functions) and reports each run as a
// cave, in ascending VA. A run that contains any address in `avoid` (function-start /
// xref'd VAs that may be data-in-code) is skipped. `minLen` is clamped to >= 1.
std::vector<CodeCave> FindCodeCaves(const std::vector<ExecRegion>& regions,
                                    size_t minLen,
                                    const std::vector<uint64_t>& avoid = {});

// Encode a near JMP (E9 rel32) from `siteVA` to `targetVA` into `out`. Returns false
// (and leaves `out` unchanged) when the displacement does not fit in a signed 32-bit
// field (target is more than ~2GB away).
bool MakeRel32Jmp(uint64_t siteVA, uint64_t targetVA, std::vector<uint8_t>& out);

struct PlaceInput {
    uint64_t              siteVA  = 0;  // start of the span being replaced
    size_t                origLen = 0;  // total length of the original instruction span
    std::vector<uint8_t>  newBody;      // compiled, position-independent patch body
    std::vector<CodeCave> caves;        // candidate caves (FindCodeCaves output)
    bool                  allowAlloc = false; // live: may request a fresh RWX region
    uint64_t              allocVA    = 0;      // a caller-allocated region to use
    bool                  allocVAValid = false;// distinguishes an allocation at VA 0 from none
    uint8_t               nop = 0x90;          // pad byte
};

// Plan the placement. Never throws; failures are reported via status + reason.
PlaceResult PlacePatch(const PlaceInput& in);

} // namespace ds
