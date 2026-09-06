#include "AtomicFile.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <limits>
#include <mutex>
#include <new>
#include <stdexcept>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace ds::atomic_file {
namespace fs = std::filesystem;

namespace {

// Atomic installation protects readers from torn bytes. Serializing the small
// transactions also prevents two writers from racing the stable backup name.
std::mutex gAtomicFileMutex;

fs::path siblingScratchPath(const fs::path& target, const char* role,
                            uint64_t attempt) {
    static std::atomic<uint64_t> sequence{0};
    const uint64_t seq = sequence.fetch_add(1, std::memory_order_relaxed);
    const uint64_t tick = static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    fs::path scratch = target;
    scratch += ".";
    scratch += role;
    scratch += "." + std::to_string(tick) + "." + std::to_string(seq) +
               "." + std::to_string(attempt);
    return scratch;
}

#ifdef _WIN32
bool writeFreshFile(const fs::path& path, std::string_view data,
                    bool& alreadyExists) {
    alreadyExists = false;
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                                nullptr, CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                                nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        const DWORD error = ::GetLastError();
        alreadyExists = error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS;
        return false;
    }

    bool ok = true;
    size_t offset = 0;
    while (offset < data.size()) {
        const size_t remaining = data.size() - offset;
        const DWORD chunk = static_cast<DWORD>(
            std::min<size_t>(remaining, 0x7FFFFFFFu));
        DWORD written = 0;
        if (!::WriteFile(file, data.data() + offset, chunk, &written, nullptr) ||
            written != chunk) {
            ok = false;
            break;
        }
        offset += written;
    }
    if (ok && !::FlushFileBuffers(file)) ok = false;
    if (!::CloseHandle(file)) ok = false;
    if (!ok) ::DeleteFileW(path.c_str());
    return ok;
}

bool installReplacement(const fs::path& target, const fs::path& temp) {
    const DWORD attrs = ::GetFileAttributesW(target.c_str());
    const bool targetExists = attrs != INVALID_FILE_ATTRIBUTES;
    if (targetExists && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        ::DeleteFileW(temp.c_str());
        return false;
    }

    if (targetExists) {
        // ReplaceFile performs the primary swap atomically. Preserve its old
        // target under a unique name first, then promote that file to the stable
        // `.bak` path without ever exposing partially-written contents.
        fs::path stagedBackup;
        for (uint64_t attempt = 0; attempt < 32; ++attempt) {
            stagedBackup = siblingScratchPath(target, "old", attempt);
            if (::GetFileAttributesW(stagedBackup.c_str()) == INVALID_FILE_ATTRIBUTES)
                break;
            stagedBackup.clear();
        }
        if (stagedBackup.empty()) {
            ::DeleteFileW(temp.c_str());
            return false;
        }
        if (::ReplaceFileW(target.c_str(), temp.c_str(), stagedBackup.c_str(),
                           REPLACEFILE_WRITE_THROUGH, nullptr, nullptr)) {
            const fs::path backup = BackupPath(target);
            if (!::MoveFileExW(stagedBackup.c_str(), backup.c_str(),
                               MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                // The new primary is complete, but report the incomplete backup
                // rotation so callers retain a visible dirty/failure state. A
                // prior stable backup, if any, is still untouched; do not leak
                // the uniquely-named staging file into the preferences folder.
                ::DeleteFileW(stagedBackup.c_str());
                return false;
            }
            return true;
        }

        // The target can disappear between the attribute query and ReplaceFile.
        if (::GetFileAttributesW(target.c_str()) == INVALID_FILE_ATTRIBUTES &&
            ::MoveFileExW(temp.c_str(), target.c_str(),
                          MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            return true;
        ::DeleteFileW(temp.c_str());
        return false;
    }

    if (::MoveFileExW(temp.c_str(), target.c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return true;
    ::DeleteFileW(temp.c_str());
    return false;
}
#else
bool writeFreshFile(const fs::path& path, std::string_view data,
                    bool& alreadyExists) {
    std::error_code ec;
    alreadyExists = fs::exists(path, ec) && !ec;
    if (alreadyExists || ec) return false;
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) return false;
    file.write(data.data(), static_cast<std::streamsize>(data.size()));
    file.flush();
    const bool ok = static_cast<bool>(file);
    file.close();
    return ok && static_cast<bool>(file);
}

bool installReplacement(const fs::path& target, const fs::path& temp) {
    std::error_code ec;
    if (fs::is_directory(target, ec)) {
        fs::remove(temp, ec);
        return false;
    }
    ec.clear();
    if (fs::exists(target, ec) && !ec) {
        fs::copy_file(target, BackupPath(target),
                      fs::copy_options::overwrite_existing, ec);
        if (ec) {
            fs::remove(temp, ec);
            return false;
        }
    }
    ec.clear();
    fs::rename(temp, target, ec);
    if (!ec) return true;
    fs::remove(temp, ec);
    return false;
}
#endif

bool readUnlocked(const fs::path& path, std::string& out, size_t maxBytes) {
    try {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) return false;
        const std::streampos end = file.tellg();
        if (end < 0) return false;
        const auto bytes = static_cast<uintmax_t>(end);
        if (bytes > static_cast<uintmax_t>(maxBytes) ||
            bytes > static_cast<uintmax_t>((std::numeric_limits<std::streamsize>::max)()))
            return false;

        std::string candidate(static_cast<size_t>(bytes), '\0');
        file.seekg(0, std::ios::beg);
        if (!file) return false;
        if (!candidate.empty()) {
            file.read(candidate.data(), static_cast<std::streamsize>(candidate.size()));
            if (file.gcount() != static_cast<std::streamsize>(candidate.size())) return false;
        }
        // Force an observation of any deferred stream error without requiring EOF.
        if (file.bad()) return false;
        out = std::move(candidate);
        return true;
    } catch (const std::bad_alloc&) {
        return false;
    } catch (const std::length_error&) {
        return false;
    }
}

} // namespace

fs::path BackupPath(const fs::path& path) {
    fs::path backup = path;
    backup += ".bak";
    return backup;
}

bool Read(const fs::path& path, std::string& out, size_t maxBytes) {
    std::lock_guard<std::mutex> lock(gAtomicFileMutex);
    std::string candidate;
    if (!readUnlocked(path, candidate, maxBytes)) return false;
    out = std::move(candidate);
    return true;
}

ReadSource ReadValidated(const fs::path& path, std::string& out,
                         const std::function<bool(std::string_view)>& validate,
                         size_t maxBytes) {
    std::lock_guard<std::mutex> lock(gAtomicFileMutex);
    std::string candidate;
    if (readUnlocked(path, candidate, maxBytes) && validate(candidate)) {
        out = std::move(candidate);
        return ReadSource::Primary;
    }
    candidate.clear();
    if (readUnlocked(BackupPath(path), candidate, maxBytes) && validate(candidate)) {
        out = std::move(candidate);
        return ReadSource::Backup;
    }
    return ReadSource::None;
}

bool Write(const fs::path& path, std::string_view data) {
    std::lock_guard<std::mutex> lock(gAtomicFileMutex);
    if (path.empty()) return false;
    std::error_code ec;
    const fs::path parent = path.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec || !fs::is_directory(parent, ec) || ec) return false;
    }

    for (uint64_t attempt = 0; attempt < 32; ++attempt) {
        const fs::path temp = siblingScratchPath(path, "tmp", attempt);
        bool alreadyExists = false;
        if (!writeFreshFile(temp, data, alreadyExists)) {
            if (alreadyExists) continue;
            return false;
        }
        return installReplacement(path, temp);
    }
    return false;
}

} // namespace ds::atomic_file
