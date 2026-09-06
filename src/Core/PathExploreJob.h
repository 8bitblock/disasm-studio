#pragma once
//
// PathExploreJob.h
// The F3 entry the AnalysisService worker / UI calls for STATIC (file-image) path
// exploration: build a CFG from the region and walk it as a bounded path tree via a
// structural ISymCfg. Without the symbolic engine this yields a real control-flow
// look-ahead map (forks at every conditional, tags rets/indirect jumps); the
// live-debugger-seeded concolic explore (input solving, overflow tags) is the
// own-thread follow-up. Kept in its own TU so PathExplore stays engine/binary-free.
//
#include "PathExplore.h"
#include "CFG.h"
#include "../Disasm/IDisassembler.h"   // Arch, IDisassembler

#include <cstdint>

namespace ds {

class BinaryFile;

PathTree PathExploreJob(const BinaryFile& bin, IDisassembler& dis, Arch arch, uint64_t rootVA,
                        const ExploreConfig& cfg = {},
                        const NoreturnCallResolver& isNoreturnCall = {});

} // namespace ds
