#pragma once
//
// Project.h
// Per-binary analysis state that survives a restart: user comments, symbol
// renames, bookmarks, breakpoints (+ conditions), accumulated byte patches, the
// last cursor, and free-form notes. Persisted as a JSON sidecar keyed by the
// binary's content hash, with a small recent-projects index so the Projects tab
// is backed by real data.
//
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "ConnectionSchema.h"

namespace ds {

struct PjBookmark   { uint64_t address = 0; std::string label; };
struct PjBreakpoint { uint64_t address = 0; std::string condition; };
struct PjPatch      { uint64_t address = 0; std::vector<uint8_t> orig, bytes; };

// Make `cur` (the bytes currently at [va, va+cur.size()), as read from the patched
// image or live memory) PRISTINE by substituting the saved `orig` of every recorded
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
// best-effort N-sample confidence badge). F2 inline hot-patch source (C/Python) keyed
// by the patch site, so the editor reopens with the code that produced a patch.
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

    // ---- analysis annotations (the things worth persisting) ----
    std::unordered_map<uint64_t, std::string> comments;     // addr -> user comment
    std::unordered_map<uint64_t, std::string> names;        // addr -> user rename
    std::unordered_map<uint64_t, std::string> algorithmLabels; // data VA -> confirmed algorithm label
    std::vector<PjBookmark>                    bookmarks;
    std::vector<uint64_t>                      breakpoints;
    std::unordered_map<uint64_t, std::string>  bpConditions; // addr -> condition
    std::unordered_map<uint64_t, uint32_t>     bpEveryN;     // addr -> break every Nth hit (absent/0/1 = every)
    std::vector<PjPatch>                        patches;
    std::vector<PjSynthesis>                    syntheses;      // F1 saved synthesis results
    std::vector<PjHotPatch>                     hotPatches;     // F2 inline C/Python sources
    std::vector<PjLabel>                        labels;         // class/method/field/resource/event labels
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
               !bookmarks.empty() || !breakpoints.empty() || !patches.empty() ||
               !syntheses.empty() || !hotPatches.empty() || !labels.empty() ||
               connNonDefault ||
               !notes.empty() || !watches.empty() || lastCursorValid;
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
bool LoadProject(uint64_t hash, ProjectState& out);   // false if no sidecar exists
bool SaveProject(const ProjectState& st);             // writes sidecar + upserts recents

// ---- recents index ----
std::vector<RecentEntry> LoadRecents();
bool RemoveRecent(uint64_t hash);

// ---- (de)serialization, split out so it is unit-testable without a filesystem ----
std::string SerializeProject(const ProjectState& st);
bool        DeserializeProject(const std::string& text, ProjectState& out);

} // namespace ds
