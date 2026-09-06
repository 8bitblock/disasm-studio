#pragma once
//
// AttachImagePolicy.h
// Pure policy for choosing the static-analysis document on a fresh native
// debugger attach.  A mapped image from an older session has no durable target
// identity, so it is never reused across the attach edge.  Hosted-DLL launches
// are deferred to their exact LOAD_DLL retarget path instead of analyzing the
// rundll32/custom-host main image.
//

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

struct AttachSessionIdentity {
    uint32_t pid = 0;
    uint64_t generation = 0;

    constexpr explicit operator bool() const {
        return pid != 0 && generation != 0;
    }
};

// Stable backing-file identity captured from the exact image handle supplied by
// CREATE_PROCESS/LOAD_DLL.  Paths alone are not an image identity: the file may
// have been atomically replaced at the same spelling after a document was read.
struct AttachedFileIdentity {
    bool valid = false;
    uint64_t volumeSerial = 0;
    uint64_t fileIndex = 0;
    uint64_t fileSize = 0;
    uint64_t lastWriteTime = 0;
};

constexpr bool SameAttachedFileIdentity(const AttachedFileIdentity& left,
                                        const AttachedFileIdentity& right) {
    return left.valid && right.valid &&
           left.volumeSerial == right.volumeSerial &&
           left.fileIndex == right.fileIndex &&
           left.fileSize == right.fileSize &&
           left.lastWriteTime == right.lastWriteTime;
}

constexpr bool SameAttachSession(AttachSessionIdentity left,
                                 AttachSessionIdentity right) {
    return static_cast<bool>(left) && static_cast<bool>(right) &&
           left.pid == right.pid && left.generation == right.generation;
}

enum class AttachMainImageAction : unsigned char {
    KeepMatchingFileDocument = 0,
    OpenEphemeralMainImage,
    DeferToHostedDllTarget,
};

struct AttachMainImageState {
    bool hostedDllLaunch = false;
    bool activeLoaded = false;
    bool activeMapped = false;
    bool activePe = false;
    bool activeArchitectureMatchesSession = false;
    bool activeFullPathMatchesMain = false;
    // True only when the active document bytes still equal the named disk file
    // and that file has the same stable identity as CREATE_PROCESS's image
    // handle.  Unavailable evidence fails closed to a live-memory capture.
    bool activeBackingFileMatchesMain = false;
};

// This policy is evaluated only on a fresh debugger-session edge.  Consequently
// an already-open mapped image necessarily belongs to an older/unproven session
// and must be recaptured even when its base/name happen to be reused.
constexpr AttachMainImageAction DecideAttachMainImage(
    const AttachMainImageState& state) {
    if (state.hostedDllLaunch)
        return AttachMainImageAction::DeferToHostedDllTarget;
    if (state.activeLoaded && !state.activeMapped && state.activePe &&
        state.activeArchitectureMatchesSession &&
        state.activeFullPathMatchesMain &&
        state.activeBackingFileMatchesMain)
        return AttachMainImageAction::KeepMatchingFileDocument;
    return AttachMainImageAction::OpenEphemeralMainImage;
}

namespace attach_image_detail {

inline bool IsSeparator(char c) { return c == '\\' || c == '/'; }

inline bool IsAsciiAlpha(char c) {
    const unsigned char value = static_cast<unsigned char>(c);
    return (value >= 'A' && value <= 'Z') ||
           (value >= 'a' && value <= 'z');
}

inline char LowerAscii(char c) {
    const unsigned char value = static_cast<unsigned char>(c);
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : c;
}

inline bool StartsWithAsciiInsensitive(std::string_view value,
                                       std::string_view prefix) {
    if (value.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i)
        if (LowerAscii(value[i]) != LowerAscii(prefix[i])) return false;
    return true;
}

} // namespace attach_image_detail

// Deterministic Windows full-path normalization for debugger image identity.
// Inputs are already absolute paths supplied by BinaryFile/Toolhelp; no current
// directory or filesystem lookup participates.  Non-absolute or malformed paths
// return empty so callers fail closed and capture the live main image.
inline std::string NormalizeAttachedImagePath(std::string_view input) {
    using namespace attach_image_detail;
    if (input.empty() || input.find('\0') != std::string_view::npos) return {};

    std::string path(input);
    for (char& c : path) {
        if (c == '/') c = '\\';
        c = LowerAscii(c);
    }

    // Win32 loader paths commonly use either extended-length spelling.  Map
    // both onto the ordinary drive/UNC namespace before component processing.
    if (StartsWithAsciiInsensitive(path, "\\\\?\\unc\\"))
        path = "\\\\" + path.substr(8);
    else if (StartsWithAsciiInsensitive(path, "\\\\?\\") ||
             StartsWithAsciiInsensitive(path, "\\??\\"))
        path.erase(0, 4);

    std::string root;
    size_t cursor = 0;
    bool driveRoot = false;
    if (path.size() >= 3 &&
        IsAsciiAlpha(path[0]) &&
        path[1] == ':' && IsSeparator(path[2])) {
        root.assign(path.data(), 3); // drive-root prefix, including separator
        cursor = 3;
        driveRoot = true;
    } else if (path.size() >= 5 && IsSeparator(path[0]) && IsSeparator(path[1])) {
        cursor = 2;
        const size_t serverEnd = path.find('\\', cursor);
        if (serverEnd == std::string::npos || serverEnd == cursor) return {};
        const size_t shareBegin = serverEnd + 1;
        const size_t shareEnd = path.find('\\', shareBegin);
        const size_t actualShareEnd = shareEnd == std::string::npos
                                    ? path.size() : shareEnd;
        if (actualShareEnd == shareBegin) return {};
        root = "\\\\" + path.substr(cursor, serverEnd - cursor) + "\\" +
               path.substr(shareBegin, actualShareEnd - shareBegin);
        cursor = actualShareEnd;
        while (cursor < path.size() && IsSeparator(path[cursor])) ++cursor;
    } else {
        return {};
    }

    std::vector<std::string> components;
    while (cursor < path.size()) {
        while (cursor < path.size() && IsSeparator(path[cursor])) ++cursor;
        const size_t begin = cursor;
        while (cursor < path.size() && !IsSeparator(path[cursor])) ++cursor;
        if (begin == cursor) continue;
        std::string component = path.substr(begin, cursor - begin);
        if (component == ".") continue;
        if (component == "..") {
            if (components.empty()) return {};
            components.pop_back();
            continue;
        }
        components.push_back(std::move(component));
    }

    std::string normalized = std::move(root);
    for (const std::string& component : components) {
        if (!driveRoot || normalized.size() != 3) normalized.push_back('\\');
        normalized += component;
    }
    return normalized;
}

inline bool AttachedImagePathsMatch(std::string_view activePath,
                                    std::string_view mainPath) {
    const std::string active = NormalizeAttachedImagePath(activePath);
    return !active.empty() && active == NormalizeAttachedImagePath(mainPath);
}

// Exact module provenance used by frame-boundary live-document publication and
// later FILE->LIVE address translation.  The debugger session generation and
// PID are checked by the caller; this comparison prevents an unload/base reuse
// or a same-leaf module in another directory from satisfying the module half.
struct AttachedModuleIdentity {
    uint64_t base = 0;
    uint64_t size = 0; // zero means Windows could not publish SizeOfImage
    std::string name;
    std::string path;
    // Monotone within one debugger session.  Base/path/size can all repeat
    // after UNLOAD_DLL followed by a replacement LOAD_DLL, so they do not by
    // themselves identify the captured mapping incarnation.
    uint64_t loadGeneration = 0;
};

inline bool AttachedModuleNamesMatch(std::string_view left,
                                     std::string_view right) {
    using namespace attach_image_detail;
    if (left.empty() || left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i)
        if (LowerAscii(left[i]) != LowerAscii(right[i])) return false;
    return true;
}

inline bool AttachedModuleIdentityMatches(const AttachedModuleIdentity& expected,
                                          const AttachedModuleIdentity& actual) {
    if (!expected.base || expected.base != actual.base) return false;
    if (expected.size && actual.size && expected.size != actual.size) return false;
    if (expected.loadGeneration &&
        expected.loadGeneration != actual.loadGeneration)
        return false;

    if (!expected.path.empty()) {
        if (actual.path.empty()) return false;
        // The expected spelling normally came from this same debugger module
        // record, so retain exact raw equality for paths Windows reports in an
        // NT form which the conservative canonicalizer deliberately rejects.
        if (expected.path == actual.path) return true;
        return AttachedImagePathsMatch(expected.path, actual.path);
    }
    if (!actual.path.empty()) return false;
    return AttachedModuleNamesMatch(expected.name, actual.name);
}

} // namespace ds
