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

namespace ds {

struct PjBookmark   { uint64_t address = 0; std::string label; };
struct PjBreakpoint { uint64_t address = 0; std::string condition; };
struct PjPatch      { uint64_t address = 0; std::vector<uint8_t> orig, bytes; };
// F1 clean-room synthesis result accepted by the user (the cleaned pseudo-C + the
// best-effort N-sample confidence badge). F2 inline hot-patch source (C/Python) keyed
// by the patch site, so the editor reopens with the code that produced a patch.
struct PjSynthesis  { uint64_t address = 0; uint32_t size = 0; std::string pseudoC;
                      uint32_t samplesPassed = 0, samplesTotal = 0; bool z3Equivalent = false;
                      std::string reasoning; };
struct PjHotPatch   { uint64_t address = 0; std::string lang; std::string source; };

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
    std::vector<PjPatch>                        patches;
    std::vector<PjSynthesis>                    syntheses;      // F1 saved synthesis results
    std::vector<PjHotPatch>                     hotPatches;     // F2 inline C/Python sources
    uint64_t                                    lastCursor = 0;
    std::string                                 notes;
    std::vector<std::string>                    watches;        // watch-panel expressions

    // Drop everything tied to a specific binary (called when switching targets).
    void reset() { *this = ProjectState{}; }
    // True if there is anything worth saving.
    bool hasContent() const {
        return !comments.empty() || !names.empty() || !algorithmLabels.empty() ||
               !bookmarks.empty() || !breakpoints.empty() || !patches.empty() ||
               !syntheses.empty() || !hotPatches.empty() ||
               !notes.empty() || !watches.empty() || lastCursor != 0;
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
