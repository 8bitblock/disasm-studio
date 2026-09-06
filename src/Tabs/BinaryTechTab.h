#pragma once
#include "ITab.h"
#include "../Core/DocumentResultIdentity.h"
#include "../Core/TechScan.h"
#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace ds {

// Binary Tech: run a "tech scan" that detects real capabilities/techniques in
// the loaded binary (imports, packer sections, byte patterns); select a
// capability to inspect the associated code and jump to it in the Binary View.
class BinaryTechTab final : public ITab {
public:
    const char* name() const override { return "Binary Tech"; }
    void render(AppContext& ctx) override;

private:
    void runTechScan(AppContext& ctx);
    void pollTechScan(const DocumentResultIdentity& currentIdentity);
    void cancelTechScan(const char* status);

    struct WorkerResult {
        uint64_t request = 0;
        DocumentResultIdentity owner;
        std::vector<Capability> capabilities;
        std::string error;
    };

    std::vector<Capability> caps_;     // from ScanCapabilities (Core/TechScan)
    DocumentResultIdentity owner_;
    DocumentResultIdentity pendingOwner_;
    int   selected_ = -1;
    float listWidth_ = 0.0f;       // retained master/detail splitter width
    bool  scanned_  = false;
    bool  pending_  = false;
    std::string status_;
    char  filter_[64] = "";

    // Declared last so its destructor requests stop and joins before the mutex
    // and ready-result storage are destroyed.
    std::atomic<uint64_t> requestSerial_{0};
    std::mutex readyMutex_;
    std::optional<WorkerResult> ready_;
    std::jthread worker_;
};

} // namespace ds
