#pragma once
//
// Synthesis.h
// F1 "clean-room symbolic synthesis": simplify a SINGLE loop-free / call-free /
// syscall-free x86-64 region into an equivalent clean expression, VERIFIED by N-sample
// blackbox I/O equivalence (the Syntia/msynth substitute for a formal proof — the
// "pragmatic, clearly-labelled" posture). Refuses out-of-envelope regions instead of
// emitting wrong code. Pure-Core: depends on ExprAst/Simplify + the SymEngine facade
// (ISymEngine/ISolver) by reference, so it is unit-tested with a mock (no Triton).
//
#include "ExprAst.h"
#include "SymEngine.h"
#include "../Disasm/IDisassembler.h"   // ds::Instruction

#include <cstdint>
#include <string>
#include <vector>

namespace ds {

struct SynthesisOptions {
    uint32_t samples = 1024;        // random I/O samples for the equivalence check
    uint64_t seed    = 0xD15A53ull; // deterministic RNG seed (reproducible badge)
    bool     useZ3   = false;       // also attempt a solver equivalence check
};

struct SynthResult {
    bool        inEnvelope    = false;  // region was inside the synthesizable envelope
    std::string rejectedReason;         // why not (when !inEnvelope or no result)
    uint64_t    regionStart   = 0;
    uint32_t    regionSize    = 0;
    std::vector<SymValue> outputs;      // simplified output expressions
    std::string cleanedPseudoC;         // human-readable result for the Synthesis tab
    std::vector<uint8_t> asmBytes;      // optional re-emitted machine code (later)
    bool        haveAsm       = false;
    uint32_t    samplesPassed = 0;
    uint32_t    samplesTotal  = 0;
    double      confidence    = 0.0;    // samplesPassed / samplesTotal (best-effort)
    bool        z3Equivalent  = false;  // solver proved orig==simplified (when useZ3)
    std::string reasoning;              // short note for the UI
};

struct EnvelopeReport { bool inEnvelope = false; std::string reason; };

// Decide whether [lo,hi) is inside the synthesizable envelope: no CALL, no syscall/int,
// no REP-string loop, no back-edge (loop), no branch leaving the region.
EnvelopeReport CheckEnvelope(const std::vector<Instruction>& insns, uint64_t lo, uint64_t hi);

// Full F1 pipeline. `insns` covers [lo,hi); `inputs` marks the symbolic locations;
// `seed` is the concrete starting state the verifier mutates per sample.
SynthResult Synthesize(const std::vector<Instruction>& insns, uint64_t lo, uint64_t hi,
                       const std::vector<SymbolicInput>& inputs, const SeedSource& seed,
                       ISymEngine& eng, ISolver& solver, const SynthesisOptions& opt);

} // namespace ds
