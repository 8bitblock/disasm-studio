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
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace ds {

class ConnectionsTab final : public ITab {
public:
    const char* name() const override { return "Connections"; }
    void render(AppContext& ctx) override;

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

    void pollAllConnections();
    void renderPayloadCapture(AppContext& ctx);   // live send/recv buffer viewer
    void renderLocalApiFramework(AppContext& ctx);

    ProcessManager           pm_;
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
    // payload capture (debugger send/recv tap) viewer state
    std::vector<NetCapture>  caps_;            // cached copy of recent captures
    size_t                   capCount_ = 0;    // last-seen total (refetch trigger)
    int                      capSel_   = -1;    // selected capture index into caps_
    bool                     capHex_   = false; // hex dump vs text view
    char                     capFilter_[64] = "";
    std::string              capLogStatus_;
    std::vector<ConnRecord>  log_;
    std::unordered_map<uint32_t, std::string> pidNames_;
    uint32_t                 lastPollTick_  = 0;
    uint32_t                 namesPollTick_ = 0;
    bool                     auto_      = true;
    bool                     activeOnly_ = false;
    bool                     tcpOnly_    = false;
    bool                     attachedOnly_ = false;   // scope to the debugged process
    char                     filter_[64] = "";
    bool                     estatsTried_  = false;   // logged the admin hint once
    bool                     estatsWorked_ = false;
};

} // namespace ds
