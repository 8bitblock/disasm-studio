#pragma once
//
// Project.h
// Per-binary analysis state that survives a restart: user comments, symbol
// renames, bookmarks, breakpoints (+ conditions), accumulated byte patches, the
// last cursor, and free-form notes. Persisted as a JSON sidecar keyed by the
// binary's content hash, with a small recent-projects index so the Projects tab
// is backed by real data.
//
#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "ConnectionSchema.h"
#include "GameMakerDebug.h"
#include "../Disasm/IDisassembler.h"

namespace ds {

struct PjBookmark   { uint64_t address = 0; std::string label; };
struct PjBreakpoint { uint64_t address = 0; std::string condition; };
// Patch records remain in one global vector because its order is the exact
// application order. `patchSetId == 0` is the backward-compatible Ungrouped
// set used by pre-v4 projects and by callers that have not selected a named
// experiment. Named set ids are stable project-local identities, not vector
// indices, so renaming or reordering the presentation does not retarget bytes.
struct PjPatch {
    uint64_t address = 0;
    std::vector<uint8_t> orig, bytes;
    uint64_t patchSetId = 0;
};

struct PjPatchSet {
    uint64_t    id = 0; // zero is reserved for the implicit Ungrouped set
    std::string name;
    bool        enabled = true;
};

// The project stores one ordered patch record per start VA. Replacing that
// record in place is safe only when the complete tracked span is unchanged;
// otherwise a shorter replacement could leave an old patched tail untracked.
inline bool PatchRecordCanBeReplacedInPlace(const PjPatch& existing,
                                            size_t replacementSize) noexcept {
    return existing.bytes.size() == replacementSize &&
           existing.orig.size() == replacementSize;
}

// Parse the patch dialog's raw-byte spelling as one complete value.  A valid
// prefix is never published: malformed text such as "90 GG" and an incomplete
// trailing byte such as "90 A" both leave `out` empty and fail closed.
inline bool ParseCompletePatchHex(const char* text,
                                  std::vector<uint8_t>& out) {
    out.clear();
    if (!text) return false;

    auto nibble = [](unsigned char c) noexcept -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    std::vector<uint8_t> parsed;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(text);
    while (*p && std::isspace(*p)) ++p;
    while (*p) {
        const int high = nibble(*p++);
        if (high < 0 || !*p) return false;
        const int low = nibble(*p++);
        if (low < 0) return false;
        parsed.push_back(static_cast<uint8_t>((high << 4) | low));
        while (*p && std::isspace(*p)) ++p;
    }
    if (parsed.empty()) return false;
    out = std::move(parsed);
    return true;
}
// Persisted linear-listing choice for one loader section. RVA + name form the
// stable key: vector position is deliberately not used because a parser may add
// or reorder modeled sections in a later build.
struct PjSectionView { uint64_t rva = 0; std::string name; bool visible = false; bool folded = true; };
// Exact identity of a named raw-analysis root. Kept separate from BinaryFile's
// runtime model so the project serializer stays dependency-light.
struct PjRawLandmark { uint64_t address = 0; std::string name; std::string evidence; };

// Version-3 analyst decisions. These records are deliberately dependency-light:
// they describe authoritative intent without borrowing FunctionAnalyzer or
// CodeDataClassifier types, so projects remain readable even when derived-analysis
// schemas change. A valid address of zero is represented directly (never by a
// sentinel); optional properties have explicit validity states.
enum class PjFunctionAction : uint8_t { Define = 0, Undefine };
enum class PjFunctionMode : uint8_t { Unspecified = 0, ARM, Thumb };
enum class PjOverrideBool : uint8_t { Unspecified = 0, False, True };
enum class PjDataKind : uint8_t { Code = 0, Data, String, PointerTable, JumpTable };

struct PjFunctionOverride {
    uint64_t         address = 0;
    PjFunctionAction action = PjFunctionAction::Define;
    bool             exactExtentValid = false;
    uint64_t         exactSize = 0; // exclusive extent is [address,address+exactSize)
    PjOverrideBool   noreturn = PjOverrideBool::Unspecified;
    std::string      callingConvention;
    std::string      prototype;
    PjFunctionMode   mode = PjFunctionMode::Unspecified;
};

struct PjDataOverride {
    uint64_t    address = 0;
    uint64_t    size = 0; // authoritative half-open span [address,address+size)
    PjDataKind  kind = PjDataKind::Data;
    std::string type;     // optional analyst type spelling
};

// Immutable worker snapshot. Keeping it separate prevents a background analysis
// job from observing ProjectState while the UI edits or replaces that state.
struct ProjectAnalysisOverrides {
    std::vector<PjFunctionOverride> functions;
    std::vector<PjDataOverride>     data;

    bool empty() const { return functions.empty() && data.empty(); }
};

// Make `cur` (the bytes currently at [va, va+cur.size()), as read from the patched
// FILE image) PRISTINE by substituting the saved `orig` of every recorded
// patch overlapping the span. Each recorded orig is pristine by induction (it was
// itself substituted when captured), so the result is the true pre-patch bytes.
// Used when capturing a new patch's `orig` so overlapping patches revert exactly.
inline void SubstitutePristine(uint64_t va, std::vector<uint8_t>& cur,
                               const std::vector<PjPatch>& patches) {
    for (const auto& p : patches) {
        const uint64_t pLo = p.address, pHi = p.address + p.orig.size();
        const uint64_t lo = (va > pLo) ? va : pLo;
        const uint64_t hi = (va + (uint64_t)cur.size() < pHi) ? va + (uint64_t)cur.size() : pHi;
        for (uint64_t a = lo; a < hi; ++a) cur[(size_t)(a - va)] = p.orig[(size_t)(a - pLo)];
    }
}
// F1 clean-room synthesis result accepted by the user (the cleaned pseudo-C + the
// best-effort N-sample confidence badge). F2 inline hot-patch source keyed by the
// patch site. The free-form language string deliberately remains backward compatible:
// legacy Python sources are retained for read-only display, never run.
struct PjSynthesis  { uint64_t address = 0; uint32_t size = 0; std::string pseudoC;
                      uint32_t samplesPassed = 0, samplesTotal = 0; bool z3Equivalent = false;
                      std::string reasoning; };
struct PjHotPatch   { uint64_t address = 0; std::string lang; std::string source; };
struct PjLabel      { std::string targetKind; std::string target; std::string label;
                      float confidence = 1.0f; std::string note; };

struct ProjectState {
    // ---- identity / metadata ----
    uint64_t    hash = 0;          // binary content hash (sidecar key); 0 = none
    std::string binaryPath;
    std::string arch;              // "x86" / "x64" / "ARM" / "ARM64" / ...
    std::string engine;            // "Zydis" / "Capstone" (disassembler choice)
    std::string name;              // display name (defaults to file name)
    std::string status = "analyzed";
    int64_t     lastOpenedUnix = 0;
    // A raw blob has no header from which its mapping can be reconstructed.
    // Persist the analyst-selected base/entry/landmarks so reopening by recent
    // project cannot shift every saved address. rawEntryExplicit preserves VA 0.
    bool                     rawMappingSaved = false;
    uint64_t                 rawImageBase = 0;
    uint64_t                 rawEntry = 0;
    bool                     rawEntryExplicit = false;
    bool                     rawBigEndian = false;
    // Full append-only DecoderFeatures mask.  rawRiscvCompressed remains as a
    // compatibility mirror for existing v1-v3 sidecars and older builds.
    uint32_t                 rawDecoderFeatureBits = kDecoderFeatureRiscvCompressed;
    bool                     rawRiscvCompressed = true;
    std::vector<PjRawLandmark> rawLandmarks;

    // ---- analysis annotations (the things worth persisting) ----
    std::unordered_map<uint64_t, std::string> comments;     // addr -> user comment
    std::unordered_map<uint64_t, std::string> names;        // addr -> user rename
    std::unordered_map<uint64_t, std::string> algorithmLabels; // data VA -> confirmed algorithm label
    std::vector<PjFunctionOverride>           functionOverrides; // authoritative; heuristic results yield
    std::vector<PjDataOverride>               dataOverrides;     // authoritative code/data span decisions
    std::vector<PjBookmark>                    bookmarks;
    std::vector<uint64_t>                      breakpoints;
    std::unordered_map<uint64_t, std::string>  bpConditions; // addr -> condition
    std::unordered_map<uint64_t, uint32_t>     bpEveryN;     // addr -> break every Nth hit (absent/0/1 = every)
    // Version 5: GML intent uses archive/code/offset identities. These are never
    // native addresses and do not grant permission to attach/inject/arm a helper.
    std::vector<GmlSavedBreakpoint>             gmlBreakpoints;
    std::vector<GmlSavedWatch>                  gmlWatches; // global/unique-object only
    std::vector<PjPatch>                        patches;
    // Presentation order only. Patch application always follows `patches` so
    // enabling/disabling a set cannot silently reorder surviving records.
    std::vector<PjPatchSet>                     patchSets;
    std::vector<PjSynthesis>                    syntheses;      // F1 saved synthesis results
    std::vector<PjHotPatch>                     hotPatches;     // F2 sources; legacy Python is read-only
    std::vector<PjLabel>                        labels;         // class/method/field/resource/event labels
    bool                                        listingLayoutSaved = false;
    bool                                        peHeaderVisible = false;
    bool                                        peHeaderFolded  = true;
    std::vector<PjSectionView>                  listingSections; // keyed by (rva,name), not index
    uint64_t                                    lastCursor = 0;
    bool                                        lastCursorValid = false; // distinguishes saved VA 0 from no cursor
    std::string                                 notes;
    std::vector<std::string>                    watches;        // watch-panel expressions
    ConnectionConfig                            connection;     // local API framework config (disabled by default)
    std::vector<ConnectionEnvelope>             connectionEvents; // event timeline accepted through the schema

    // Drop everything tied to a specific binary (called when switching targets).
    void reset() { *this = ProjectState{}; }
    // True if there is anything worth saving.
    bool hasContent() const {
        const bool connNonDefault =
            connection.enabled || connection.authEnabled || !connection.localhostOnly ||
            !connection.accessToken.empty() || !connectionEvents.empty();
        return !comments.empty() || !names.empty() || !algorithmLabels.empty() ||
               !functionOverrides.empty() || !dataOverrides.empty() ||
               !bookmarks.empty() || !breakpoints.empty() || !patches.empty() ||
               !gmlBreakpoints.empty() || !gmlWatches.empty() ||
               !patchSets.empty() ||
               !syntheses.empty() || !hotPatches.empty() || !labels.empty() ||
               listingLayoutSaved ||
               connNonDefault ||
               !notes.empty() || !watches.empty() || lastCursorValid || rawMappingSaved;
    }

    ProjectAnalysisOverrides analysisOverrides() const {
        return { functionOverrides, dataOverrides };
    }
};

struct RecentEntry {
    uint64_t    hash = 0;
    std::string path, name, arch, status;
    int64_t     lastOpenedUnix = 0;
};

// ---- filesystem locations ----
// Base dir: %APPDATA%/DisasmStudio/projects on Windows, else $HOME/.disasmstudio
// /projects. Overridable with the DS_PROJECTS_DIR env var (used by tests).
std::string ProjectsDir();
std::string ProjectPathForHash(uint64_t hash);

// ---- sidecar load / save (also maintains the recents index on save) ----
// Loads fall back to the last known-good .bak. Saves use a flushed sibling temp
// and atomic replacement.  The sidecar is authoritative; the recents index is a
// rebuildable convenience and therefore never turns a successful sidecar commit
// into a failed save/dirty document.
enum class ProjectLoadAttempt : uint8_t {
    NotTried = 0,
    Missing,           // no file exists at this candidate path
    Unavailable,       // exists, but is unreadable, over budget, or exhausted resources
    Malformed,         // JSON/schema/limit validation failed
    IdentityMismatch,  // valid sidecar belongs to another content hash
    Loaded,
};
inline bool ProjectLoadAttemptRequiresWarning(ProjectLoadAttempt attempt) {
    return attempt == ProjectLoadAttempt::Unavailable ||
           attempt == ProjectLoadAttempt::Malformed ||
           attempt == ProjectLoadAttempt::IdentityMismatch;
}
enum class ProjectLoadSource : uint8_t { None = 0, Primary, Backup };
struct ProjectLoadResult {
    bool               loaded = false;
    ProjectLoadSource  source = ProjectLoadSource::None;
    ProjectLoadAttempt primary = ProjectLoadAttempt::NotTried;
    ProjectLoadAttempt backup = ProjectLoadAttempt::NotTried;
    std::string        error; // empty on primary success; recovery/failure detail otherwise

    bool recoveredFromBackup() const {
        return loaded && source == ProjectLoadSource::Backup;
    }
};

struct ProjectSaveResult {
    // True once all authoritative state is durable.  This is also true when the
    // project has no sidecar-worthy content, because there is then nothing to
    // commit.  A recents-only failure is reported separately as a warning.
    bool        saved = false;
    bool        sidecarWritten = false;
    bool        recentsAttempted = false;
    bool        recentsUpdated = false;
    std::string error;   // hard sidecar/validation failure
    std::string warning; // non-authoritative recents maintenance failure
};

ProjectLoadResult LoadProjectDetailed(uint64_t hash, ProjectState& out);
bool LoadProject(uint64_t hash, ProjectState& out);
ProjectSaveResult SaveProjectDetailed(const ProjectState& st);
// Compatibility wrapper: reports only whether authoritative state was saved.
bool SaveProject(const ProjectState& st);

// ---- recents index ----
std::vector<RecentEntry> LoadRecents();
bool RemoveRecent(uint64_t hash); // false if absent or the recents commit failed

// ---- (de)serialization, split out so it is unit-testable without a filesystem ----
std::string SerializeProject(const ProjectState& st);
bool        DeserializeProject(const std::string& text, ProjectState& out);

} // namespace ds
