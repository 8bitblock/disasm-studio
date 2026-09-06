#pragma once
//
// ConnectionsTab.h
// A standalone network-activity tab: a system-wide view of every process's TCP
// and UDP endpoints (IPv4 + IPv6) — where each one is going — with HISTORY
// (closed connections are retained) and live DATA-TRANSFER counters (bytes in/
// out and a per-second rate) for active TCP connections via the TCP ESTATS API.
//
// Connection enumeration uses the IP Helper API (GetExtendedTcp/UdpTable, owner
// PID). Byte counts need TCP ESTATS collection, which is best-effort and may
// require Administrator; when unavailable the rows still show, just without
// byte/rate numbers.
//
#include "ITab.h"
#include "../Core/ConnectionSchema.h"
#include "../Core/ProcessManager.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ds {

class ConnectionsTab final : public ITab {
public:
    ConnectionsTab();
    ~ConnectionsTab() override;

    const char* name() const override { return "Connections"; }
    void render(AppContext& ctx) override;
    void requestLiveObservation(DocumentId document, uint64_t imageGeneration) {
        networkView_ = 1;
        observationRequiresMatchingTarget_ = static_cast<bool>(document) && imageGeneration != 0;
        observationExpectedDocument_ = document;
        observationExpectedImageGeneration_ = imageGeneration;
        observationNextRefresh_ = 0.0;
    }

private:
    // One observed endpoint, retained across polls so closed connections persist
    // as history. Tick fields are GetTickCount() milliseconds.
    struct ConnRecord {
        std::string proto;       // "TCP" / "TCP6" / "UDP" / "UDP6"
        std::string local;       // ip:port
        std::string remote;      // ip:port  ("*" for UDP / listeners)
        std::string state;       // TCP state name, or "listen"
        uint32_t    pid       = 0;
        std::string proc;        // owning process name (best-effort)
        uint32_t    firstSeen = 0;
        uint32_t    lastSeen  = 0;
        bool        active    = false;   // present in the most recent poll
        // Data transfer (TCP only; cumulative since ESTATS collection began).
        bool        haveBytes = false;
        uint64_t    bytesIn   = 0, bytesOut = 0;
        uint64_t    prevIn    = 0, prevOut  = 0;   // previous poll (for the rate)
        double      rateIn    = 0.0, rateOut = 0.0; // bytes/sec, last interval
    };

    void pollAllConnections();                     // worker-only table/history update
    void requestConnectionPoll(bool clearHistory = false);
    void pumpConnectionPoll();
    void connectionWorkerLoop(std::stop_token stop);
    void renderPayloadCapture(AppContext& ctx);   // live send/recv buffer viewer
    void renderLocalApiFramework(AppContext& ctx);

    struct PollJob { uint64_t epoch = 0; bool clearHistory = false; };
    struct PollResult {
        uint64_t epoch = 0;
        std::vector<ConnRecord> log;
        uint32_t pollTick = 0;
        bool estatsTried = false;
        bool estatsWorked = false;
        std::string warning;
        std::string error;
    };

    ProcessManager           pm_;             // used only by the polling worker
    // Local API framework (schema/config/event timeline only; no listener here).
    uint64_t                 apiProjectHash_ = ~0ull;
    char                     apiTokenBuf_[256] = "";
    char                     apiEventBuf_[2048] =
        "{\n"
        "  \"type\": \"event\",\n"
        "  \"source\": \"tool\",\n"
        "  \"project_id\": \"\",\n"
        "  \"artifact_id\": \"\",\n"
        "  \"address\": \"\",\n"
        "  \"method\": \"\",\n"
        "  \"payload\": {},\n"
        "  \"timestamp\": \"\"\n"
        "}";
    std::string              apiStatus_;
    // Typed Server Watch viewer state. The legacy payload-only capture list is
    // intentionally not exposed; payloads belong to their observation event.
    bool                     capHex_   = false; // selected-event hex vs text view
    std::string              capLogStatus_;
    int                      networkView_ = 0;     // 0 connection history, 1 guided server watch
    NetworkObservation       observation_;
    double                   observationNextRefresh_ = 0.0;
    uint64_t                 observationSelectedSequence_ = 0;
    char                     observationFilter_[96] = "";
    bool                     observationRequiresMatchingTarget_ = false;
    DocumentId               observationExpectedDocument_{};
    uint64_t                 observationExpectedImageGeneration_ = 0;
    std::vector<ConnRecord>  log_;
    uint32_t                 lastPollTick_  = 0;
    bool                     auto_      = true;
    bool                     activeOnly_ = false;
    bool                     tcpOnly_    = false;
    bool                     attachedOnly_ = false;   // scope to the debugged process
    char                     filter_[64] = "";
    bool                     estatsTried_  = false;   // logged the admin hint once
    bool                     estatsWorked_ = false;
    std::string              pollWarning_;
    std::string              pollError_;

    // Authoritative history/rate state belongs to this worker. Completed
    // snapshots are copied off-thread and moved into log_ in O(1) on render().
    std::vector<ConnRecord>  workerLog_;
    std::unordered_map<uint32_t, std::string> workerPidNames_;
    uint32_t                 workerLastPollTick_ = 0;
    uint32_t                 workerNamesPollTick_ = 0;
    bool                     workerEstatsTried_ = false;
    bool                     workerEstatsWorked_ = false;
    std::string              workerPollWarning_;
    std::mutex               pollMutex_;
    std::condition_variable  pollCv_;
    std::optional<PollJob>   pendingPoll_;
    std::optional<PollResult> readyPoll_;
    std::atomic<uint64_t>    desiredPollEpoch_{0};
    std::atomic<bool>        pollRunning_{false};
    std::jthread             pollWorker_;
};

} // namespace ds
