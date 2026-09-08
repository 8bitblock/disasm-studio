#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <future>
#include <span>
#include <string>

namespace ds {
struct ArtifactWriteResult {
    bool success = false;
    std::filesystem::path path;
    uint64_t bytes = 0;
    std::string error;
    std::string warning;
};

// A producer writes only to an exclusively-created sibling temporary file.
// Any producer/write/flush/close failure leaves the destination untouched.
// Installation is atomic and never deletes the previous destination first.
class ArtifactOutput {
public:
    ~ArtifactOutput();
    ArtifactOutput(const ArtifactOutput&) = delete;
    ArtifactOutput& operator=(const ArtifactOutput&) = delete;
    bool write(std::span<const uint8_t> bytes);
    const std::string& error() const { return error_; }
private:
    ArtifactOutput() = default;
    bool open(const std::filesystem::path& destination);
    bool commit(bool replace);
    std::filesystem::path destination_, temporary_;
    void* handle_ = nullptr;
    uint64_t bytes_ = 0;
    std::string error_;
    friend ArtifactWriteResult WriteArtifact(const std::filesystem::path&,
        const std::function<bool(ArtifactOutput&, std::string&)>&, bool);
};
ArtifactWriteResult WriteArtifact(const std::filesystem::path& destination,
    const std::function<bool(ArtifactOutput&, std::string&)>& producer,
    bool replace = true);
ArtifactWriteResult WriteArtifactBytes(const std::filesystem::path& destination,
    std::span<const uint8_t> bytes, bool replace = true);

// UI-thread admission/polling; exactly one owned job including its unconsumed
// completion. Shutdown joins the accepted save; no callback runs on the worker.
class ArtifactWriteService {
public:
    ~ArtifactWriteService();
    bool start(std::function<ArtifactWriteResult()> ownedJob, std::string& error);
    bool pending() const { return result_.valid(); }
    bool take(ArtifactWriteResult& result);
private:
    std::future<ArtifactWriteResult> result_;
};
} // namespace ds
