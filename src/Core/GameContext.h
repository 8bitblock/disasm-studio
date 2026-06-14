#pragma once
//
// GameContext.h
// Lightweight game/crackme workflow model (additions.md sections D/H). It turns
// already-computed evidence (strings, function names, runtime findings, and
// algorithm constants) into grouped, honest hints for the UI. Pure Core: no ImGui,
// no Win32, no decoder dependency.
//
#include "AnalysisJobs.h"
#include "AlgoScan.h"
#include "Findings.h"
#include "RuntimeScan.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ds {

enum class GameStringCategory : uint8_t {
    Asset,
    Config,
    Save,
    Replay,
    Network,
    UI,
    Error,
    Debug,
    ScriptRuntime,
    Other
};

const char* GameStringCategoryName(GameStringCategory c);

enum class GameFunctionKind : uint8_t {
    UpdateLoop,
    Render,
    Input,
    EntityObject,
    ResourceLoad,
    Audio,
    Network,
    VtableVirtual,
    NativeBoundary,
    Validation,
    Encoding,
    Timer,
    Callback,
    ConfigSave
};

const char* GameFunctionKindName(GameFunctionKind k);

struct GameStringFinding {
    uint64_t           address = 0;
    std::string        text;
    GameStringCategory category = GameStringCategory::Other;
    float              confidence = 0.0f;
    std::string        evidence;
};

struct GameFunctionFinding {
    uint64_t         address = 0;
    std::string      name;
    GameFunctionKind kind = GameFunctionKind::UpdateLoop;
    float            confidence = 0.0f;
    std::string      evidence;
};

struct GameContextInput {
    std::vector<StrResult>  strings;
    std::vector<FuncResult> functions;
    std::vector<AlgoMatch>  algorithms;
    RuntimeScanResult       runtime;
};

struct GameContextReport {
    std::vector<GameStringFinding>   strings;
    std::vector<GameFunctionFinding> functions;
    std::vector<Finding>             runtimeBoundaries;
    std::vector<Finding>             crackmeHints;

    bool empty() const {
        return strings.empty() && functions.empty() &&
               runtimeBoundaries.empty() && crackmeHints.empty();
    }
};

GameContextReport BuildGameContext(const GameContextInput& in);

} // namespace ds
