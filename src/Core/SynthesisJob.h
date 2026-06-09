#pragma once
//
// SynthesisJob.h
// The F1 entry point the UI / AnalysisService calls: decode a region [lo,hi) from the
// binary, seed a SymEngine from its bytes, mark the inferred argument registers
// symbolic, and run the Synthesis pipeline. Kept in its own TU (not Synthesis.cpp) so
// Synthesis stays engine-free and cl-testable; this file binds the real
// MakeSymEngine/MakeSolver. With the stub engine (engines feature off) it returns a
// clean "engine unavailable" result rather than failing.
//
#include "Synthesis.h"
#include "../Disasm/IDisassembler.h"   // Arch, IDisassembler

#include <cstdint>

namespace ds {

class BinaryFile;

SynthResult SynthesizeJob(const BinaryFile& bin, IDisassembler& dis, Arch arch,
                          uint64_t lo, uint64_t hi, const SynthesisOptions& opt);

} // namespace ds
