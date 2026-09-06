#pragma once

// Crash-resistant small-file persistence shared by project sidecars, recents,
// and application preferences.  A successful write has been flushed and
// installed with a same-directory atomic replacement.  Once a primary exists,
// the immediately preceding primary is retained as `<path>.bak`.

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>

namespace ds::atomic_file {

enum class ReadSource {
    None,
    Primary,
    Backup,
};

std::filesystem::path BackupPath(const std::filesystem::path& path);

// Reads at most maxBytes. Files larger than the limit and partial/I/O failures
// are rejected without modifying `out`.
bool Read(const std::filesystem::path& path, std::string& out,
          size_t maxBytes = static_cast<size_t>(-1));

// Tries the primary first and accepts it only when the complete payload passes
// `validate`. An unreadable or malformed primary falls back to the stable
// backup. `out` is unchanged if neither copy is valid.
ReadSource ReadValidated(
    const std::filesystem::path& path,
    std::string& out,
    const std::function<bool(std::string_view)>& validate,
    size_t maxBytes = static_cast<size_t>(-1));

// Writes a unique sibling temporary file, flushes it, then atomically installs
// it. False means the durable transaction did not fully complete.
bool Write(const std::filesystem::path& path, std::string_view data);

} // namespace ds::atomic_file
