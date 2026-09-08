#include "ArtifactWrite.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <exception>

namespace ds {
namespace {
std::string ioError(const char* action, DWORD code = ::GetLastError()) {
    return std::string(action) + " (Windows error " + std::to_string(code) + ").";
}
}
ArtifactOutput::~ArtifactOutput() {
    if (handle_) ::CloseHandle(static_cast<HANDLE>(handle_));
    if (!temporary_.empty()) ::DeleteFileW(temporary_.c_str());
}
bool ArtifactOutput::open(const std::filesystem::path& destination) {
    destination_ = destination;
    if (destination.empty() || destination.filename().empty() ||
        destination.filename().native().find(L':') != std::wstring::npos) {
        error_ = "The output path must name a file, without an alternate data stream.";
        return false;
    }
    static std::atomic<uint64_t> sequence{0};
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        // The scratch leaf is independent of the requested filename, which
        // may spell a reserved Windows device name. Never open that name for I/O.
        auto candidate = destination.parent_path() /
            (L".ds-write-" + std::to_wstring(::GetCurrentProcessId()) + L"-" +
             std::to_wstring(sequence.fetch_add(1)) + L".tmp");
        HANDLE file = ::CreateFileW(candidate.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (file != INVALID_HANDLE_VALUE) {
            handle_ = file;
            temporary_ = std::move(candidate);
            return true;
        }
        const DWORD code = ::GetLastError();
        if (code != ERROR_FILE_EXISTS && code != ERROR_ALREADY_EXISTS) {
            error_ = ioError("Could not create the sibling temporary output", code);
            return false;
        }
    }
    error_ = "Could not reserve a unique sibling temporary output.";
    return false;
}
bool ArtifactOutput::write(std::span<const uint8_t> bytes) {
    if (!error_.empty()) return false;
    if (!handle_) { error_ = "Output is not open."; return false; }
    while (!bytes.empty()) {
        const DWORD chunk = static_cast<DWORD>(std::min<size_t>(bytes.size(), 4 * 1024 * 1024));
        DWORD written = 0;
        if (!::WriteFile(static_cast<HANDLE>(handle_), bytes.data(), chunk, &written, nullptr)) {
            error_ = ioError("Could not write the complete output");
            return false;
        }
        if (written != chunk) {
            error_ = "The output write was incomplete.";
            return false;
        }
        bytes_ += written;
        bytes = bytes.subspan(written);
    }
    return true;
}
bool ArtifactOutput::commit(bool replace) {
    if (!error_.empty()) return false;
    if (!::FlushFileBuffers(static_cast<HANDLE>(handle_))) {
        error_ = ioError("Could not flush the output");
        return false;
    }
    HANDLE file = static_cast<HANDLE>(handle_);
    handle_ = nullptr;
    if (!::CloseHandle(file)) {
        error_ = ioError("Could not close the output");
        return false;
    }
    // Both names are siblings: MoveFileEx uses a same-volume rename. Do not
    // permit COPY_ALLOWED or fall back to deleting/truncating the destination.
    const DWORD flags = MOVEFILE_WRITE_THROUGH | (replace ? MOVEFILE_REPLACE_EXISTING : 0);
    if (!::MoveFileExW(temporary_.c_str(), destination_.c_str(), flags)) {
        error_ = ioError("Could not atomically install the output");
        return false;
    }
    temporary_.clear();
    return true;
}
ArtifactWriteResult WriteArtifact(const std::filesystem::path& destination,
    const std::function<bool(ArtifactOutput&, std::string&)>& producer, bool replace) {
    ArtifactWriteResult result;
    result.path = destination;
    try {
        ArtifactOutput output;
        if (!output.open(destination)) { result.error = output.error(); return result; }
        if (!producer(output, result.error)) {
            if (result.error.empty()) result.error = output.error().empty()
                ? "Output generation failed." : output.error();
            return result;
        }
        if (!output.commit(replace)) { result.error = output.error(); return result; }
        result.bytes = output.bytes_;
        result.success = true;
    } catch (const std::exception& error) { result.error = error.what(); }
    catch (...) { result.error = "Unexpected output generation failure."; }
    return result;
}
ArtifactWriteResult WriteArtifactBytes(const std::filesystem::path& destination,
    std::span<const uint8_t> bytes, bool replace) {
    return WriteArtifact(destination, [bytes](ArtifactOutput& output, std::string&) {
        return output.write(bytes);
    }, replace);
}
ArtifactWriteService::~ArtifactWriteService() { if (result_.valid()) result_.wait(); }
bool ArtifactWriteService::start(std::function<ArtifactWriteResult()> ownedJob,
                                 std::string& error) {
    error.clear();
    if (pending()) { error = "A file save is still pending; wait for its result."; return false; }
    try {
        result_ = std::async(std::launch::async, [job = std::move(ownedJob)] {
            try { return job(); }
            catch (const std::exception& failure) {
                ArtifactWriteResult result; result.error = failure.what(); return result;
            } catch (...) {
                ArtifactWriteResult result; result.error = "Unexpected file save failure."; return result;
            }
        });
        return true;
    } catch (const std::exception& failure) { error = failure.what(); return false; }
}
bool ArtifactWriteService::take(ArtifactWriteResult& result) {
    if (!result_.valid() || result_.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
        return false;
    result = result_.get();
    return true;
}
} // namespace ds
