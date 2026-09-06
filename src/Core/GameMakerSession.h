#pragma once

#include "DebugTargetIdentity.h"
#include "GameMakerDebug.h"
#include "GameMakerRunner.h"
#include <memory>
#include <string>
#include <vector>

namespace ds {
struct GameMakerArchive;
class GameMakerSession;

enum class GameMakerSessionState {
    Disconnected, Preparing, Loading, Initializing, Installing, Running, Paused,
    Disabling, Inert, Failed
};

// Immutable publication. A stop pointer conveys inspection evidence only; edits
// must return its full identity to Debugger, which owns the held Win32 event.
struct GameMakerSessionSnapshot {
    GameMakerSessionState state = GameMakerSessionState::Disconnected;
    DebugTargetIdentity target;
    uint64_t generation = 0, revision = 0, archiveHash = 0;
    uint64_t helperBase = 0, runnerBase = 0;
    std::string runnerName, status, error, lastEdit;
    uint32_t requestedBreakpoints = 0, boundBreakpoints = 0;
    GmlRunnerCapabilities capabilities;
    bool instructionStopsVerified = false;
    bool mappingRetained = false;
    std::shared_ptr<const GameMakerArchive> archive;
    std::shared_ptr<const GmlHelperStop> stop;
    bool ready() const noexcept {
        return state == GameMakerSessionState::Running || state == GameMakerSessionState::Paused;
    }
};
} // namespace ds
