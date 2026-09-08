#include "ConnectionsTab.h"
// Winsock before windows.h; iphlpapi for the owner-PID tables + TCP ESTATS.
#include <winsock2.h>
#include <windows.h>
#include <commdlg.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>   // TCP_ESTATS_DATA_RW_v0 / _ROD_v0 for per-connection byte counts
#include "../Core/CrackmeTriage.h"
#include "../Core/NetworkApiCatalog.h"
#include "../Core/NetworkEndpoint.h"
#include "../Ui/Fonts.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>

// ws2tcpip aliases these identifiers to imported functions. They also name
// strongly typed observation enum values below, where macro substitution would
// corrupt the switch labels.
#ifdef GetNameInfoA
#undef GetNameInfoA
#endif
#ifdef GetNameInfoW
#undef GetNameInfoW
#endif

#pragma comment(lib, "iphlpapi.lib")

namespace ds {

ConnectionsTab::ConnectionsTab() {
    pollWorker_ = std::jthread([this](std::stop_token stop) {
        connectionWorkerLoop(stop);
    });
}

ConnectionsTab::~ConnectionsTab() {
    desiredPollEpoch_.fetch_add(1, std::memory_order_acq_rel);
    {
        std::lock_guard lock(pollMutex_);
        pendingPoll_.reset();
        readyPoll_.reset();
    }
    pollWorker_.request_stop();
    pollCv_.notify_all();
    if (pollWorker_.joinable()) pollWorker_.join();
}

static std::string wideToUtf8(const wchar_t* w) {
    if (!w || !*w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? (size_t)n : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    if (!s.empty() && s.back() == '\0') s.pop_back();
    return s;
}

static bool choosePayloadLogFile(std::string& out) {
    wchar_t file[MAX_PATH] = L"network_payloads.log";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"Log files\0*.log;*.txt\0All files\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrDefExt = L"log";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return false;
    out = wideToUtf8(file);
    return !out.empty();
}

static const char* tcpState(unsigned long s) {
    switch (s) {
        case MIB_TCP_STATE_CLOSED:     return "CLOSED";
        case MIB_TCP_STATE_LISTEN:     return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT:   return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD:   return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB:      return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1:  return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2:  return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING:    return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK:   return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT:  return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default:                       return "?";
    }
}

template <typename Fetch>
static DWORD fetchConnectionTableBounded(Fetch&& fetch, std::vector<uint8_t>& buffer) {
    constexpr DWORD kMaxTableBytes = 64u * 1024u * 1024u;
    DWORD size = 0;
    DWORD rc = fetch(nullptr, &size);
    if (rc == NO_ERROR && !size) { buffer.clear(); return NO_ERROR; }
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) return rc;
    for (int attempt = 0; size && attempt < 3; ++attempt) {
        if (size > kMaxTableBytes) return ERROR_NOT_ENOUGH_MEMORY;
        buffer.assign(size, 0);
        rc = fetch(buffer.data(), &size);
        if (rc == NO_ERROR) return NO_ERROR;
        if (rc != ERROR_INSUFFICIENT_BUFFER) return rc;
    }
    return rc == NO_ERROR ? ERROR_INSUFFICIENT_BUFFER : rc;
}

template <typename Table, typename Row>
static size_t boundedConnectionRows(const std::vector<uint8_t>& buffer,
                                    const Table* table) {
    constexpr size_t header = offsetof(Table, table);
    if (!table || buffer.size() < header) return 0;
    return std::min<size_t>(table->dwNumEntries,
                            (buffer.size() - header) / sizeof(Row));
}

// Read DataBytesIn/Out for one TCP connection via ESTATS, enabling collection on
// first sight. Returns false when ESTATS is unavailable (e.g. not elevated).
template <typename RowT>
static bool readEstats(const RowT& row, bool v6, uint64_t& inB, uint64_t& outB) {
    TCP_ESTATS_DATA_RW_v0 rw{};
    rw.EnableCollection = TRUE;
    // Enabling may fail (already enabled, or access denied) — that's fine; we
    // still try the read, which succeeds whenever collection is already on.
    if (v6) ::SetPerTcp6ConnectionEStats((PMIB_TCP6ROW)&row, TcpConnectionEstatsData, (UCHAR*)&rw, 0, sizeof(rw), 0);
    else    ::SetPerTcpConnectionEStats ((PMIB_TCPROW)&row,  TcpConnectionEstatsData, (UCHAR*)&rw, 0, sizeof(rw), 0);

    TCP_ESTATS_DATA_ROD_v0 rod{};
    ULONG rc = v6
        ? ::GetPerTcp6ConnectionEStats((PMIB_TCP6ROW)&row, TcpConnectionEstatsData,
                                       nullptr, 0, 0, nullptr, 0, 0, (UCHAR*)&rod, 0, sizeof(rod))
        : ::GetPerTcpConnectionEStats ((PMIB_TCPROW)&row,  TcpConnectionEstatsData,
                                       nullptr, 0, 0, nullptr, 0, 0, (UCHAR*)&rod, 0, sizeof(rod));
    if (rc != NO_ERROR) return false;
    inB  = rod.DataBytesIn;
    outB = rod.DataBytesOut;
    return true;
}

void ConnectionsTab::pollAllConnections() {
    const uint32_t now = ::GetTickCount();
    const uint32_t dtMs = workerLastPollTick_ ? (now - workerLastPollTick_) : 0;
    workerLastPollTick_ = now;

    if (workerPidNames_.empty() || (uint32_t)(now - workerNamesPollTick_) > 3000) {
        workerNamesPollTick_ = now;
        workerPidNames_.clear();
        for (const auto& p : pm_.enumerate()) workerPidNames_[p.pid] = p.name;
    }

    std::unordered_map<std::string, size_t> idx;
    idx.reserve(workerLog_.size() * 2);
    for (size_t i = 0; i < workerLog_.size(); ++i) {
        workerLog_[i].active = false;
        workerLog_[i].rateIn = workerLog_[i].rateOut = 0.0;
        idx[workerLog_[i].proto + '|' + workerLog_[i].local + '|' + workerLog_[i].remote + '|' +
            std::to_string(workerLog_[i].pid)] = i;
    }

    auto touch = [&](const char* proto, const std::string& local, const std::string& remote,
                     const std::string& state, uint32_t pid,
                     bool haveBytes, uint64_t inB, uint64_t outB) -> ConnRecord& {
        std::string key = std::string(proto) + '|' + local + '|' + remote + '|' + std::to_string(pid);
        auto it = idx.find(key);
        ConnRecord* r;
        if (it != idx.end()) { r = &workerLog_[it->second]; }
        else {
            ConnRecord nr;
            nr.proto = proto; nr.local = local; nr.remote = remote;
            nr.pid = pid; nr.firstSeen = now;
            auto pn = workerPidNames_.find(pid);
            nr.proc = (pn != workerPidNames_.end()) ? pn->second : "";
            idx[key] = workerLog_.size();
            workerLog_.push_back(std::move(nr));
            r = &workerLog_.back();
        }
        r->state = state; r->lastSeen = now; r->active = true;
        if (haveBytes) {
            if (r->haveBytes && dtMs > 0) {
                // Cumulative counters can reset if ESTATS was re-enabled; clamp.
                if (inB  >= r->prevIn)  r->rateIn  = (double)(inB  - r->prevIn)  * 1000.0 / dtMs;
                if (outB >= r->prevOut) r->rateOut = (double)(outB - r->prevOut) * 1000.0 / dtMs;
            }
            r->haveBytes = true;
            r->bytesIn = inB; r->bytesOut = outB;
            r->prevIn = inB;  r->prevOut = outB;
        }
        return *r;
    };

    std::vector<uint8_t> buf;
    bool estatsOk = false;
    workerPollWarning_.clear();
    auto failure = [&](const char* table, DWORD error) {
        if (!workerPollWarning_.empty()) workerPollWarning_ += "; ";
        workerPollWarning_ += table;
        workerPollWarning_ += " error ";
        workerPollWarning_ += std::to_string(error);
    };
    constexpr size_t kMaxRowsPerPoll = 100000;
    constexpr size_t kMaxEstatsQueriesPerPoll = 8192;
    size_t rowsProcessed = 0;
    size_t estatsQueries = 0;
    bool estatsCapped = false;
    auto admittedRows = [&](size_t rows) {
        const size_t remaining = rowsProcessed < kMaxRowsPerPoll
                               ? kMaxRowsPerPoll - rowsProcessed : 0;
        const size_t admitted = std::min(rows, remaining);
        if (admitted < rows && workerPollWarning_.find("row cap reached") == std::string::npos) {
            if (!workerPollWarning_.empty()) workerPollWarning_ += "; ";
            workerPollWarning_ += "row cap reached";
        }
        rowsProcessed += admitted;
        return admitted;
    };

    // IPv4 TCP (+ ESTATS bytes on established connections)
    DWORD rc = fetchConnectionTableBounded([&](void* data, DWORD* size) {
        return GetExtendedTcpTable(data, size, FALSE, AF_INET,
                                   TCP_TABLE_OWNER_PID_ALL, 0);
    }, buf);
    if (rc == NO_ERROR) {
        const auto* t = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
        const size_t rows = admittedRows(boundedConnectionRows<MIB_TCPTABLE_OWNER_PID,
                                                               MIB_TCPROW_OWNER_PID>(buf, t));
        for (size_t i = 0; i < rows; ++i) {
            const auto& e = t->table[i];
            const std::string ls = FormatIpv4Endpoint(
                reinterpret_cast<const uint8_t*>(&e.dwLocalAddr),
                (uint16_t)ntohs((u_short)e.dwLocalPort));
            const std::string rs = FormatIpv4Endpoint(
                reinterpret_cast<const uint8_t*>(&e.dwRemoteAddr),
                (uint16_t)ntohs((u_short)e.dwRemotePort));
            uint64_t inB = 0, outB = 0; bool hb = false;
            if (e.dwState == MIB_TCP_STATE_ESTAB &&
                estatsQueries < kMaxEstatsQueriesPerPoll) {
                ++estatsQueries;
                MIB_TCPROW row{};
                row.dwState = e.dwState; row.dwLocalAddr = e.dwLocalAddr;
                row.dwLocalPort = e.dwLocalPort; row.dwRemoteAddr = e.dwRemoteAddr;
                row.dwRemotePort = e.dwRemotePort;
                hb = readEstats(row, false, inB, outB);
                estatsOk = estatsOk || hb;
            } else if (e.dwState == MIB_TCP_STATE_ESTAB) estatsCapped = true;
            touch("TCP", ls, rs, tcpState(e.dwState), e.dwOwningPid, hb, inB, outB);
        }
    } else failure("TCP/IPv4", rc);

    // IPv6 TCP
    rc = fetchConnectionTableBounded([&](void* data, DWORD* size) {
        return GetExtendedTcpTable(data, size, FALSE, AF_INET6,
                                   TCP_TABLE_OWNER_PID_ALL, 0);
    }, buf);
    if (rc == NO_ERROR) {
        const auto* t = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buf.data());
        const size_t rows = admittedRows(boundedConnectionRows<MIB_TCP6TABLE_OWNER_PID,
                                                               MIB_TCP6ROW_OWNER_PID>(buf, t));
        for (size_t i = 0; i < rows; ++i) {
            const auto& e = t->table[i];
            const std::string ls = FormatIpv6Endpoint(
                e.ucLocalAddr, (uint16_t)ntohs((u_short)e.dwLocalPort), e.dwLocalScopeId);
            const std::string rs = FormatIpv6Endpoint(
                e.ucRemoteAddr, (uint16_t)ntohs((u_short)e.dwRemotePort), e.dwRemoteScopeId);
            uint64_t inB = 0, outB = 0; bool hb = false;
            if (e.dwState == MIB_TCP_STATE_ESTAB &&
                estatsQueries < kMaxEstatsQueriesPerPoll) {
                ++estatsQueries;
                MIB_TCP6ROW row{};
                std::memcpy(&row.LocalAddr, e.ucLocalAddr, 16);
                row.dwLocalScopeId = e.dwLocalScopeId; row.dwLocalPort = e.dwLocalPort;
                std::memcpy(&row.RemoteAddr, e.ucRemoteAddr, 16);
                row.dwRemoteScopeId = e.dwRemoteScopeId; row.dwRemotePort = e.dwRemotePort;
                row.State = (MIB_TCP_STATE)e.dwState;
                hb = readEstats(row, true, inB, outB);
                estatsOk = estatsOk || hb;
            } else if (e.dwState == MIB_TCP_STATE_ESTAB) estatsCapped = true;
            touch("TCP6", ls, rs, tcpState(e.dwState), e.dwOwningPid, hb, inB, outB);
        }
    } else failure("TCP/IPv6", rc);

    // IPv4 UDP
    rc = fetchConnectionTableBounded([&](void* data, DWORD* size) {
        return GetExtendedUdpTable(data, size, FALSE, AF_INET,
                                   UDP_TABLE_OWNER_PID, 0);
    }, buf);
    if (rc == NO_ERROR) {
        const auto* u = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf.data());
        const size_t rows = admittedRows(boundedConnectionRows<MIB_UDPTABLE_OWNER_PID,
                                                               MIB_UDPROW_OWNER_PID>(buf, u));
        for (size_t i = 0; i < rows; ++i) {
            const auto& e = u->table[i];
            const std::string ls = FormatIpv4Endpoint(
                reinterpret_cast<const uint8_t*>(&e.dwLocalAddr),
                (uint16_t)ntohs((u_short)e.dwLocalPort));
            touch("UDP", ls, "*", "listen", e.dwOwningPid, false, 0, 0);
        }
    } else failure("UDP/IPv4", rc);

    // IPv6 UDP
    rc = fetchConnectionTableBounded([&](void* data, DWORD* size) {
        return GetExtendedUdpTable(data, size, FALSE, AF_INET6,
                                   UDP_TABLE_OWNER_PID, 0);
    }, buf);
    if (rc == NO_ERROR) {
        const auto* u = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buf.data());
        const size_t rows = admittedRows(boundedConnectionRows<MIB_UDP6TABLE_OWNER_PID,
                                                               MIB_UDP6ROW_OWNER_PID>(buf, u));
        for (size_t i = 0; i < rows; ++i) {
            const auto& e = u->table[i];
            const std::string ls = FormatIpv6Endpoint(
                e.ucLocalAddr, (uint16_t)ntohs((u_short)e.dwLocalPort), e.dwLocalScopeId);
            touch("UDP6", ls, "*", "listen", e.dwOwningPid, false, 0, 0);
        }
    } else failure("UDP/IPv6", rc);

    if (estatsCapped) {
        if (!workerPollWarning_.empty()) workerPollWarning_ += "; ";
        workerPollWarning_ += "TCP ESTATS query cap reached";
    }
    workerEstatsTried_ = true;
    workerEstatsWorked_ = workerEstatsWorked_ || estatsOk;

    constexpr size_t kCap = 8000;
    if (workerLog_.size() > kCap) {
        std::sort(workerLog_.begin(), workerLog_.end(), [](const ConnRecord& a, const ConnRecord& b) {
            if (a.active != b.active) return a.active > b.active;
            return a.lastSeen > b.lastSeen;
        });
        workerLog_.resize(kCap);
    }
}

void ConnectionsTab::requestConnectionPoll(bool clearHistory) {
    const uint64_t epoch = desiredPollEpoch_.fetch_add(1, std::memory_order_acq_rel) + 1;
    {
        std::lock_guard lock(pollMutex_);
        // A queued destructive clear must not be lost if auto-refresh replaces
        // the pending command before the worker reaches it.
        if (pendingPoll_ && pendingPoll_->clearHistory) clearHistory = true;
        pendingPoll_ = PollJob{epoch, clearHistory}; // latest command wins
        readyPoll_.reset();
        pollRunning_.store(true, std::memory_order_release);
    }
    if (clearHistory) {
        // The visible history disappears immediately; the worker performs the
        // authoritative clear before it publishes the matching empty snapshot.
        log_.clear();
        lastPollTick_ = ::GetTickCount();
        pollWarning_.clear();
    }
    pollError_.clear();
    pollCv_.notify_one();
}

void ConnectionsTab::pumpConnectionPoll() {
    std::optional<PollResult> ready;
    {
        std::lock_guard lock(pollMutex_);
        if (readyPoll_) {
            ready = std::move(readyPoll_);
            readyPoll_.reset();
        }
    }
    if (!ready || ready->epoch != desiredPollEpoch_.load(std::memory_order_acquire))
        return;
    if (!ready->error.empty()) {
        pollError_ = std::move(ready->error);
    } else {
        log_ = std::move(ready->log);
        lastPollTick_ = ready->pollTick;
        estatsTried_ = ready->estatsTried;
        estatsWorked_ = ready->estatsWorked;
        pollWarning_ = std::move(ready->warning);
        pollError_.clear();
    }
    pollRunning_.store(false, std::memory_order_release);
}

void ConnectionsTab::connectionWorkerLoop(std::stop_token stop) {
    for (;;) {
        PollJob job;
        {
            std::unique_lock lock(pollMutex_);
            pollCv_.wait(lock, [&] {
                return stop.stop_requested() || pendingPoll_.has_value();
            });
            if (stop.stop_requested()) return;
            job = *pendingPoll_;
            pendingPoll_.reset();
        }

        PollResult result;
        result.epoch = job.epoch;
        std::vector<ConnRecord> oldLog;
        std::unordered_map<uint32_t, std::string> oldNames;
        uint32_t oldPollTick = workerLastPollTick_;
        uint32_t oldNamesTick = workerNamesPollTick_;
        bool oldEstatsTried = workerEstatsTried_;
        bool oldEstatsWorked = workerEstatsWorked_;
        std::string oldWarning;
        bool rollbackReady = false;
        try {
            if (job.clearHistory) {
                workerLog_.clear();
                workerPidNames_.clear();
                workerLastPollTick_ = ::GetTickCount();
                workerNamesPollTick_ = 0;
                workerEstatsTried_ = false;
                workerEstatsWorked_ = false;
                workerPollWarning_.clear();
            } else {
                oldLog = workerLog_;
                oldNames = workerPidNames_;
                oldWarning = workerPollWarning_;
                rollbackReady = true;
                pollAllConnections();
            }
            if (stop.stop_requested() ||
                desiredPollEpoch_.load(std::memory_order_acquire) != job.epoch)
                continue;
            result.log = workerLog_; // bounded copy stays on the worker
            result.pollTick = workerLastPollTick_;
            result.estatsTried = workerEstatsTried_;
            result.estatsWorked = workerEstatsWorked_;
            result.warning = workerPollWarning_;
        } catch (const std::exception& error) {
            if (rollbackReady) {
                workerLog_ = std::move(oldLog);
                workerPidNames_ = std::move(oldNames);
                workerLastPollTick_ = oldPollTick;
                workerNamesPollTick_ = oldNamesTick;
                workerEstatsTried_ = oldEstatsTried;
                workerEstatsWorked_ = oldEstatsWorked;
                workerPollWarning_ = std::move(oldWarning);
            }
            result.error = std::string("network polling failed: ") + error.what();
        } catch (...) {
            if (rollbackReady) {
                workerLog_ = std::move(oldLog);
                workerPidNames_ = std::move(oldNames);
                workerLastPollTick_ = oldPollTick;
                workerNamesPollTick_ = oldNamesTick;
                workerEstatsTried_ = oldEstatsTried;
                workerEstatsWorked_ = oldEstatsWorked;
                workerPollWarning_ = std::move(oldWarning);
            }
            result.error = "network polling failed: unknown worker error";
        }
        {
            std::lock_guard lock(pollMutex_);
            if (desiredPollEpoch_.load(std::memory_order_acquire) != job.epoch)
                continue;
            readyPoll_ = std::move(result);
        }
    }
}

static std::string humanBytes(uint64_t b) {
    char out[32];
    if (b >= 1024ull * 1024 * 1024) std::snprintf(out, sizeof(out), "%.2f GB", (double)b / (1024.0*1024*1024));
    else if (b >= 1024ull * 1024)   std::snprintf(out, sizeof(out), "%.1f MB", (double)b / (1024.0*1024));
    else if (b >= 1024)             std::snprintf(out, sizeof(out), "%.1f KB", (double)b / 1024.0);
    else                            std::snprintf(out, sizeof(out), "%llu B", (unsigned long long)b);
    return out;
}
static std::string humanRate(double bps) {
    char out[32];
    if (bps >= 1024.0 * 1024) std::snprintf(out, sizeof(out), "%.1f MB/s", bps / (1024.0*1024));
    else if (bps >= 1024.0)   std::snprintf(out, sizeof(out), "%.0f KB/s", bps / 1024.0);
    else                      std::snprintf(out, sizeof(out), "%.0f B/s", bps);
    return out;
}

static bool parseAddrString(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    const char* p = s.c_str();
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) p += 2;
    char* end = nullptr;
    unsigned long long v = std::strtoull(p, &end, 16);
    if (end == p || *end != 0) return false;
    out = (uint64_t)v;
    return true;
}

void ConnectionsTab::renderLocalApiFramework(AppContext& ctx) {
    ConnectionConfig& cfg = ctx.staticProject().connection;
    if (apiProjectHash_ != ctx.staticProject().hash) {
        apiProjectHash_ = ctx.staticProject().hash;
        std::snprintf(apiTokenBuf_, sizeof(apiTokenBuf_), "%s", cfg.accessToken.c_str());
    }

    ImGui::SeparatorText("Local API");
    ImGui::TextColored(theme::col::warn(),
                       "Not included in DisasmStudio 1.0: no listener is shipped in this build.");
    bool enabled = cfg.enabled;
    ImGui::BeginDisabled();
    ImGui::Checkbox("Enabled", &enabled);
    ImGui::SameLine();
    bool localOnly = cfg.localhostOnly;
    ImGui::Checkbox("Localhost only", &localOnly);
    ImGui::SameLine();
    bool auth = cfg.authEnabled;
    ImGui::Checkbox("Auth", &auth);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.0f * theme::UiScale());
    ImGui::InputTextWithHint("##apitoken", "per-project token", apiTokenBuf_, sizeof(apiTokenBuf_));
    ImGui::EndDisabled();

    std::string cfgErr;
    if (!ValidateConnectionConfig(cfg, &cfgErr))
        ImGui::TextColored(theme::col::bad(), "%s", cfgErr.c_str());
    else if (cfg.enabled)
        ImGui::TextDisabled("Saved legacy setting is inert; this build never opens a listener.");
    else
        ImGui::TextDisabled("Disabled by default. Schema/event timeline are available for future local transports.");

    if (ImGui::TreeNodeEx("Event timeline", ImGuiTreeNodeFlags_DefaultOpen,
                          "Event timeline (%d)",
                          (int)ctx.staticProject().connectionEvents.size())) {
        ImGui::TextDisabled("Paste a schema message to validate and append it to the project timeline.");
        ImGui::InputTextMultiline("##apievent", apiEventBuf_, sizeof(apiEventBuf_),
                                  ImVec2(-1.0f, 96.0f * theme::UiScale()));
        if (ImGui::Button("Validate + append")) {
            ConnectionEnvelope ev;
            std::string err;
            if (DeserializeConnectionEnvelope(apiEventBuf_, ev, &err)) {
                ctx.staticProject().connectionEvents.push_back(std::move(ev));
                if (ctx.staticProject().connectionEvents.size() > 512)
                    ctx.staticProject().connectionEvents.erase(
                        ctx.staticProject().connectionEvents.begin(),
                        ctx.staticProject().connectionEvents.begin() +
                        (ctx.staticProject().connectionEvents.size() - 512));
                ctx.markProjectDirty();
                apiStatus_ = "accepted";
            } else {
                apiStatus_ = err;
            }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear events") &&
            !ctx.staticProject().connectionEvents.empty()) {
            ctx.staticProject().connectionEvents.clear();
            ctx.markProjectDirty();
        }
        if (!apiStatus_.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", apiStatus_.c_str());
        }

        if (ImGui::BeginTable("apievents", 6,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY,
                ImVec2(0, 150.0f * theme::UiScale()))) {
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 70.0f * theme::UiScale());
            ImGui::TableSetupColumn("Source", ImGuiTableColumnFlags_WidthFixed, 95.0f * theme::UiScale());
            ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 120.0f * theme::UiScale());
            ImGui::TableSetupColumn("Method", ImGuiTableColumnFlags_WidthFixed, 150.0f * theme::UiScale());
            ImGui::TableSetupColumn("Payload");
            ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 120.0f * theme::UiScale());
            ImGui::TableHeadersRow();
            for (int i = (int)ctx.staticProject().connectionEvents.size() - 1;
                 i >= 0; --i) {
                const ConnectionEnvelope& e =
                    ctx.staticProject().connectionEvents[(size_t)i];
                ImGui::TableNextRow(); ImGui::PushID(i);
                ImGui::TableNextColumn(); ImGui::TextDisabled("%s", e.type.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(e.source.c_str());
                ImGui::TableNextColumn();
                uint64_t va = 0;
                if (parseAddrString(e.address, va)) {
                    if (ImGui::Selectable(e.address.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
                        ctx.gotoAddress(va);
                } else {
                    ImGui::TextDisabled("%s", e.address.empty() ? "-" : e.address.c_str());
                }
                ImGui::TableNextColumn(); ImGui::TextUnformatted(e.method.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(e.payloadJson.c_str());
                ImGui::TableNextColumn(); ImGui::TextDisabled("%s", e.timestamp.c_str());
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        ImGui::TreePop();
    }
}

void ConnectionsTab::render(AppContext& ctx) {
    const float scale = theme::UiScale();
    const uint32_t now = ::GetTickCount();
    pumpConnectionPoll();

    static const char* views[] = { "Connection History", "Server Watch" };
    networkView_ = ui::TabStrip("##network_monitor_views", views, 2, networkView_);
    if (networkView_ == 1) {
        renderPayloadCapture(ctx);
        return;
    }

    ImGui::TextUnformatted("Connection history");
    ImGui::PushStyleColor(ImGuiCol_Text, theme::col::muted());
    ImGui::TextWrapped("Live process endpoints and traffic history. Server Watch shows debugger-observed API calls and payloads.");
    ImGui::PopStyleColor();

    // The unavailable legacy API schema is still inspectable, but it no longer
    // occupies the prime viewport above the live monitor on every visit.
    if (ImGui::CollapsingHeader("Advanced: local API schema (inactive)")) {
        renderLocalApiFramework(ctx);
        ImGui::Separator();
    }

    // The debugged process: native Win32 debugger PID, else the JDWP-injected PID.
    DbgSnapshot dbg = ctx.debug.snapshot();
    const uint32_t attachedPid = dbg.attached() ? dbg.pid
        : ctx.jdwp.snapshot().attached() ? ctx.jdwpTargetPid : 0;

    if (ImGui::Button("Refresh now")) requestConnectionPoll();
    ui::SameLineIfFits(70.0f * scale); ImGui::Checkbox("Auto", &auto_);
    ui::SameLineIfFits(105.0f * scale); ImGui::Checkbox("Active only", &activeOnly_);
    ui::SameLineIfFits(95.0f * scale); ImGui::Checkbox("TCP only", &tcpOnly_);
    ui::SameLineIfFits(185.0f * scale);
    ImGui::BeginDisabled(attachedPid == 0);
    ImGui::Checkbox("Attached process only", &attachedOnly_);
    ImGui::EndDisabled();
    if (attachedPid && ImGui::IsItemHovered())
        ImGui::SetTooltip("Show only connections owned by the debugged process (PID %u)", attachedPid);
    ui::SameLineIfFits(115.0f * scale);
    if (ImGui::Button("Clear history")) requestConnectionPoll(true);
    ui::SearchBox("##connfilter", "filter IP / port / process / PID...", filter_, sizeof(filter_), -1.0f);
    if (attachedPid == 0) attachedOnly_ = false;   // nothing attached: don't hide everything

    if (auto_) {
        ctx.wantContinuousRedraw = true;
        if (!pollRunning_.load(std::memory_order_acquire) &&
            (lastPollTick_ == 0 || (uint32_t)(now - lastPollTick_) > 1000))
            requestConnectionPoll();
    }
    if (pollRunning_.load(std::memory_order_acquire)) {
        ctx.wantContinuousRedraw = true;
        ImGui::TextDisabled("Refreshing network tables\xE2\x80\xA6");
    }
    ImGui::PushTextWrapPos();
    if (!pollError_.empty())
        ImGui::TextColored(theme::col::bad(), "%s", pollError_.c_str());
    if (!pollWarning_.empty())
        ImGui::TextColored(theme::col::warn(), "Partial refresh: %s", pollWarning_.c_str());

    if (estatsTried_ && !estatsWorked_)
        ImGui::TextColored(theme::col::muted(),
            "Byte/rate columns need TCP ESTATS \xE2\x80\x94 run the disassembler as Administrator to populate them.");
    ImGui::PopTextWrapPos();

    std::string needle = filter_;
    for (char& c : needle) c = (char)std::tolower((unsigned char)c);
    auto matches = [&](const ConnRecord& r) {
        if (activeOnly_ && !r.active) return false;
        if (tcpOnly_ && r.proto.rfind("TCP", 0) != 0) return false;
        if (attachedOnly_ && attachedPid && r.pid != attachedPid) return false;
        if (needle.empty()) return true;
        std::string hay = r.proc + ' ' + std::to_string(r.pid) + ' ' + r.local + ' ' + r.remote + ' ' + r.proto + ' ' + r.state;
        for (char& c : hay) c = (char)std::tolower((unsigned char)c);
        return hay.find(needle) != std::string::npos;
    };

    std::vector<int> view;
    view.reserve(log_.size());
    for (int i = 0; i < (int)log_.size(); ++i) if (matches(log_[i])) view.push_back(i);
    // Active first; within that, fastest-moving first; otherwise most-recent.
    std::sort(view.begin(), view.end(), [&](int a, int b) {
        const ConnRecord& x = log_[a]; const ConnRecord& y = log_[b];
        if (x.active != y.active) return x.active > y.active;
        double xr = x.rateIn + x.rateOut, yr = y.rateIn + y.rateOut;
        if (xr != yr) return xr > yr;
        return x.lastSeen > y.lastSeen;
    });

    int activeCount = 0; for (const auto& r : log_) if (r.active) ++activeCount;
    ImGui::Separator();
    ImGui::TextDisabled("%d shown / %zu tracked \xC2\xB7 %d active", (int)view.size(), log_.size(), activeCount);

    if (view.empty()) {
        if (log_.empty()) {
            ImGui::TextWrapped("No connections have been sampled yet. Use Refresh now or leave Auto enabled.");
        } else if (ui::EmptyState(DS_ICON_SEARCH, "No matching connections",
                                 "Your search or scope filters hide the tracked connections.", "Reset filters")) {
            filter_[0] = '\0';
            activeOnly_ = tcpOnly_ = attachedOnly_ = false;
        }
        return;
    }
    // Server Watch owns its own workspace. History retains the full viewport
    // regardless of whether a native debugger happens to be attached.
    const float tableH = ImGui::GetContentRegionAvail().y;
    if (ImGui::BeginTable("conn_tbl", 9,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable, ImVec2(0, tableH),
            (std::max)(ImGui::GetContentRegionAvail().x, 1100.0f * scale))) {
        ImGui::TableSetupScrollFreeze(1, 1);
        ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthFixed, 160.0f * scale);
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 48.0f * scale);
        ImGui::TableSetupColumn("Local", ImGuiTableColumnFlags_WidthFixed, 175.0f * scale);
        ImGui::TableSetupColumn("Remote (where)");
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 95.0f * scale);
        ImGui::TableSetupColumn("In", ImGuiTableColumnFlags_WidthFixed, 75.0f * scale);
        ImGui::TableSetupColumn("Out", ImGuiTableColumnFlags_WidthFixed, 75.0f * scale);
        ImGui::TableSetupColumn("Rate", ImGuiTableColumnFlags_WidthFixed, 130.0f * scale);
        ImGui::TableSetupColumn("Seen", ImGuiTableColumnFlags_WidthFixed, 110.0f * scale);
        ImGui::TableHeadersRow();

        ImGuiListClipper clip;
        clip.Begin((int)view.size());
        while (clip.Step()) {
            for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
                const ConnRecord& r = log_[view[row]];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                if (r.proc.empty()) ImGui::Text("(pid %u)", r.pid);
                else                ImGui::Text("%s (%u)", r.proc.c_str(), r.pid);
                ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", r.proto.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(r.local.c_str());
                ImGui::TableSetColumnIndex(3);
                if (r.remote == "*") ImGui::TextDisabled("*");
                else                 ImGui::TextUnformatted(r.remote.c_str());
                ImGui::TableSetColumnIndex(4); ImGui::TextDisabled("%s", r.state.c_str());
                ImGui::TableSetColumnIndex(5);
                if (r.haveBytes) ImGui::TextUnformatted(humanBytes(r.bytesIn).c_str());
                else             ImGui::TextDisabled("\xE2\x80\x94");
                ImGui::TableSetColumnIndex(6);
                if (r.haveBytes) ImGui::TextUnformatted(humanBytes(r.bytesOut).c_str());
                else             ImGui::TextDisabled("\xE2\x80\x94");
                ImGui::TableSetColumnIndex(7);
                if (r.active && (r.rateIn > 1.0 || r.rateOut > 1.0))
                    ImGui::TextColored(theme::col::accent(), "\xE2\x86\x93%s \xE2\x86\x91%s",
                                       humanRate(r.rateIn).c_str(), humanRate(r.rateOut).c_str());
                else ImGui::TextDisabled("\xE2\x80\x94");
                ImGui::TableSetColumnIndex(8);
                if (r.active) ImGui::TextColored(theme::col::good(), "\xE2\x97\x8f active");
                else          ImGui::TextColored(theme::col::muted(), "closed %us ago", (now - r.lastSeen) / 1000);
            }
        }
        ImGui::EndTable();
    }
}

// True if at least `frac` of the bytes are printable/whitespace — i.e. worth
// showing as text rather than a hex dump.
static bool mostlyText(const std::vector<uint8_t>& b, double frac = 0.75) {
    if (b.empty()) return false;
    size_t printable = 0;
    for (uint8_t c : b)
        if (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7F)) ++printable;
    return (double)printable / (double)b.size() >= frac;
}
// Printable copy: control/binary bytes -> '.', so a text box stays readable.
static std::string toText(const std::vector<uint8_t>& b) {
    std::string s; s.reserve(b.size());
    for (uint8_t c : b) {
        if (c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7F)) s.push_back((char)c);
        else if (c == '\r') {}                       // drop CR so \r\n shows as one break
        else s.push_back('.');
    }
    return s;
}
// Classic offset / hex / ascii dump.
static std::string toHexDump(const std::vector<uint8_t>& b) {
    std::string s; s.reserve(b.size() * 4);
    char line[128];
    for (size_t off = 0; off < b.size(); off += 16) {
        std::snprintf(line, sizeof(line), "%08zX  ", off);
        s += line;
        std::string ascii;
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < b.size()) {
                uint8_t c = b[off + i];
                std::snprintf(line, sizeof(line), "%02X ", c);
                s += line;
                ascii.push_back((c >= 0x20 && c < 0x7F) ? (char)c : '.');
            } else s += "   ";
            if (i == 7) s += ' ';
        }
        s += " "; s += ascii; s += '\n';
    }
    return s;
}

static const char* observationStageName(NetworkObservationStage stage) {
    switch (stage) {
    case NetworkObservationStage::ProbeStatus:    return "status";
    case NetworkObservationStage::NameResolution:return "resolve";
    case NetworkObservationStage::Connect:        return "connect";
    case NetworkObservationStage::Request:        return "request";
    case NetworkObservationStage::Response:       return "response";
    case NetworkObservationStage::Send:           return "send";
    case NetworkObservationStage::Receive:        return "receive";
    case NetworkObservationStage::HandleClosed:   return "close";
    case NetworkObservationStage::Limitation:     return "limitation";
    }
    return "event";
}

static const char* observationApiName(NetworkProbeApi api) {
    if (const NetworkProbeDescriptor* descriptor = NetworkProbeDescriptorFor(api))
        return descriptor->symbol;
    switch (api) {
    case NetworkProbeApi::ResolveAddrInfoA: return "getaddrinfo(A)";
    case NetworkProbeApi::ResolveAddrInfoW: return "getaddrinfo(W)";
    case NetworkProbeApi::GetAddrInfoExA: return "GetAddrInfoEx(A)";
    case NetworkProbeApi::GetAddrInfoExW: return "GetAddrInfoEx(W)";
    case NetworkProbeApi::GetHostByName: return "gethostbyname";
    case NetworkProbeApi::GetNameInfoA: return "getnameinfo(A)";
    case NetworkProbeApi::GetNameInfoW: return "getnameinfo(W)";
    case NetworkProbeApi::DnsQueryA: return "DnsQuery(A)";
    case NetworkProbeApi::DnsQueryW: return "DnsQuery(W)";
    case NetworkProbeApi::DnsQueryUtf8: return "DnsQuery(UTF-8)";
    case NetworkProbeApi::Connect: return "connect";
    case NetworkProbeApi::WSAConnect: return "WSAConnect";
    case NetworkProbeApi::Send: return "send";
    case NetworkProbeApi::Recv: return "recv";
    case NetworkProbeApi::WSASend: return "WSASend";
    case NetworkProbeApi::WSARecv: return "WSARecv";
    case NetworkProbeApi::SendTo: return "sendto";
    case NetworkProbeApi::RecvFrom: return "recvfrom";
    case NetworkProbeApi::WSASendTo: return "WSASendTo";
    case NetworkProbeApi::WSARecvFrom: return "WSARecvFrom";
    case NetworkProbeApi::CloseSocket: return "closesocket";
    case NetworkProbeApi::WinHttpOpen: return "WinHttpOpen";
    case NetworkProbeApi::WinHttpConnect: return "WinHttpConnect";
    case NetworkProbeApi::WinHttpOpenRequest: return "WinHttpOpenRequest";
    case NetworkProbeApi::WinHttpAddRequestHeaders: return "WinHttpAddRequestHeaders";
    case NetworkProbeApi::WinHttpSendRequest: return "WinHttpSendRequest";
    case NetworkProbeApi::WinHttpReceiveResponse: return "WinHttpReceiveResponse";
    case NetworkProbeApi::WinHttpWriteData: return "WinHttpWriteData";
    case NetworkProbeApi::WinHttpReadData: return "WinHttpReadData";
    case NetworkProbeApi::WinHttpQueryHeaders: return "WinHttpQueryHeaders";
    case NetworkProbeApi::WinHttpCloseHandle: return "WinHttpCloseHandle";
    case NetworkProbeApi::InternetOpenA: return "InternetOpen(A)";
    case NetworkProbeApi::InternetOpenW: return "InternetOpen(W)";
    case NetworkProbeApi::InternetConnectA: return "InternetConnect(A)";
    case NetworkProbeApi::InternetConnectW: return "InternetConnect(W)";
    case NetworkProbeApi::HttpOpenRequestA: return "HttpOpenRequest(A)";
    case NetworkProbeApi::HttpOpenRequestW: return "HttpOpenRequest(W)";
    case NetworkProbeApi::HttpAddRequestHeadersA: return "HttpAddRequestHeaders(A)";
    case NetworkProbeApi::HttpAddRequestHeadersW: return "HttpAddRequestHeaders(W)";
    case NetworkProbeApi::HttpSendRequestA: return "HttpSendRequest(A)";
    case NetworkProbeApi::HttpSendRequestW: return "HttpSendRequest(W)";
    case NetworkProbeApi::InternetOpenUrlA: return "InternetOpenUrl(A)";
    case NetworkProbeApi::InternetOpenUrlW: return "InternetOpenUrl(W)";
    case NetworkProbeApi::HttpSendRequestExA: return "HttpSendRequestEx(A)";
    case NetworkProbeApi::HttpSendRequestExW: return "HttpSendRequestEx(W)";
    case NetworkProbeApi::HttpEndRequestA: return "HttpEndRequest(A)";
    case NetworkProbeApi::HttpEndRequestW: return "HttpEndRequest(W)";
    case NetworkProbeApi::InternetWriteFile: return "InternetWriteFile";
    case NetworkProbeApi::InternetReadFile: return "InternetReadFile";
    case NetworkProbeApi::InternetReadFileExA: return "InternetReadFileEx(A)";
    case NetworkProbeApi::InternetReadFileExW: return "InternetReadFileEx(W)";
    case NetworkProbeApi::HttpQueryInfoA: return "HttpQueryInfo(A)";
    case NetworkProbeApi::HttpQueryInfoW: return "HttpQueryInfo(W)";
    case NetworkProbeApi::InternetCloseHandle: return "InternetCloseHandle";
    case NetworkProbeApi::UrlDownloadToFileA: return "URLDownloadToFile(A)";
    case NetworkProbeApi::UrlDownloadToFileW: return "URLDownloadToFile(W)";
    case NetworkProbeApi::UrlDownloadToCacheFileA: return "URLDownloadToCacheFile(A)";
    case NetworkProbeApi::UrlDownloadToCacheFileW: return "URLDownloadToCacheFile(W)";
    case NetworkProbeApi::UrlOpenStreamA: return "URLOpenStream(A)";
    case NetworkProbeApi::UrlOpenStreamW: return "URLOpenStream(W)";
    case NetworkProbeApi::UrlOpenBlockingStreamA: return "URLOpenBlockingStream(A)";
    case NetworkProbeApi::UrlOpenBlockingStreamW: return "URLOpenBlockingStream(W)";
    case NetworkProbeApi::Unknown: return "probe";
    }
    return "probe";
}

static std::optional<NetworkApiReturnContract>
observationReturnContract(NetworkProbeApi api) {
    const NetworkProbeDescriptor* descriptor = NetworkProbeDescriptorFor(api);
    if (!descriptor) return std::nullopt;
    return LookupNetworkApiReturnContract(descriptor->dll, descriptor->symbol);
}

static std::string observationContractSummary(
    const NetworkApiReturnContract& contract) {
    std::string text(contract.returnType);
    if (!text.empty()) text += ": ";
    text += contract.successMeaning;
    if (!contract.failureMeaning.empty()) {
        text += "; failure: ";
        text += contract.failureMeaning;
    }
    if (contract.asyncPendingPossible)
        text += "; a sentinel may mean asynchronous pending until completion/error is observed";
    return text;
}

static std::string observationOutputSummary(
    const NetworkApiReturnContract& contract) {
    std::string text;
    for (uint8_t i = 0; i < contract.outParameterCount; ++i) {
        const NetworkApiOutParameter& output = contract.outParameters[i];
        if (!text.empty()) text += "; ";
        text += "arg " + std::to_string(output.oneBasedOrdinal()) + " " +
                NetworkOutParameterRoleText(output.role);
        if (!output.meaning.empty()) text += ": " + std::string(output.meaning);
    }
    return text.empty() ? "none cataloged" : text;
}

static std::string observationOutcome(const NetworkObservationEvent& event) {
    if (!event.resultValid) return "unknown";
    const auto contract = observationReturnContract(event.api);
    if (!contract) return "raw result observed";
    const NetworkReturnDisposition disposition = InterpretNetworkApiReturn(
        *contract, event.rawResult, std::nullopt,
        event.pointerWidthBits ? event.pointerWidthBits : 64u);
    std::string text = NetworkReturnDispositionText(disposition);
    if (disposition == NetworkReturnDisposition::Success &&
        contract->zeroResultMeaning != NetworkZeroResultMeaning::None) {
        bool zeroCompletion = false;
        if (contract->returnKind == NetworkReturnKind::SignedByteCount)
            zeroCompletion = static_cast<int32_t>(event.rawResult) == 0;
        else if (event.transferredValid)
            zeroCompletion = event.transferred == 0;
        if (zeroCompletion) {
            text += " / ";
            text += NetworkZeroResultMeaningText(contract->zeroResultMeaning);
        }
    }
    return text;
}

static std::string observationRawResultText(const NetworkObservationEvent& event) {
    if (!event.resultValid) return "unavailable";
    char raw[96];
    const auto contract = observationReturnContract(event.api);
    if (contract && (contract->returnKind == NetworkReturnKind::InternetHandle ||
                     contract->returnKind == NetworkReturnKind::SocketHandle ||
                     contract->returnKind == NetworkReturnKind::Pointer)) {
        std::snprintf(raw, sizeof(raw), "0x%llX (%u-bit)",
                      (unsigned long long)event.rawResult,
                      event.pointerWidthBits ? event.pointerWidthBits : 64u);
    } else {
        std::snprintf(raw, sizeof(raw), "%lld / 0x%llX (%u-bit)",
                      (long long)(int32_t)event.rawResult,
                      (unsigned long long)event.rawResult,
                      event.pointerWidthBits ? event.pointerWidthBits : 64u);
    }
    return raw;
}

static const char* observationEvidenceName(NetworkEvidenceQuality quality) {
    switch (quality) {
    case NetworkEvidenceQuality::Unknown:   return "unknown";
    case NetworkEvidenceQuality::Heuristic: return "heuristic";
    case NetworkEvidenceQuality::Observed:  return "observed";
    case NetworkEvidenceQuality::Proven:    return "proven";
    }
    return "unknown";
}

static std::string observationSummary(const NetworkObservationEvent& event) {
    std::string value = event.endpoint;
    if (value.empty()) value = event.hostname;
    if (value.empty()) value = event.ip;
    if (event.portValid && value.find(':') == std::string::npos)
        value += ':' + std::to_string(event.port);
    const std::string& path = event.path.empty() ? event.object : event.path;
    if (!event.method.empty() || !path.empty()) {
        if (!value.empty()) value += "  ";
        value += event.method;
        if (!event.method.empty() && !path.empty()) value += ' ';
        value += path;
    }
    if (!value.empty()) return value;
    if (!event.detail.empty()) return event.detail;
    if (event.handle) {
        char value[32];
        std::snprintf(value, sizeof(value), "handle 0x%llX",
                      (unsigned long long)event.handle);
        return value;
    }
    return "network event";
}

void ConnectionsTab::renderPayloadCapture(AppContext& ctx) {
    const float scale = theme::UiScale();
    const DbgSnapshot debug = ctx.debug.snapshot();
    const bool debugLive = debug.state == DbgState::Running ||
                           debug.state == DbgState::Paused;
    bool on = ctx.debug.netTapEnabled();
    const bool expectedImageActive = observationRequiresMatchingTarget_ &&
        ctx.staticDocumentId() == observationExpectedDocument_ &&
        ctx.staticImageGeneration() == observationExpectedImageGeneration_;
    uint64_t matchingBase = 0, matchingSize = 0;
    // Runtime/static correlation is useful for both a Triage-scoped handoff and
    // an ordinary Communications watch.  The optional expected-document guard
    // controls whether observation may run; it must not disable read-only
    // correlation when the active document independently matches the debuggee.
    const bool activeRuntimeImageMatches =
        ctx.debuggerRuntimeImage(debug, matchingBase, matchingSize);
    const bool matchingTarget = expectedImageActive && activeRuntimeImageMatches;
    if (on && observationRequiresMatchingTarget_ && !matchingTarget) {
        // A triage handoff is identity-bound. If the analyst switches documents,
        // reattaches, or already had an unrelated watch running, stop before any
        // more internal probes can be planted for the wrong target.
        ctx.debug.stopNetworkObservation();
        on = false;
        observationNextRefresh_ = 0.0;
    }
    auto discardStaleObservation = [&]() {
        const NetworkProbeCoverage& cached = observation_.coverage;
        const bool cachedIdentity = cached.pid != 0 ||
                                    cached.sessionGeneration != 0;
        if (!cachedIdentity ||
            (cached.pid == debug.pid &&
             cached.sessionGeneration == debug.sessionGeneration))
            return;
        observation_ = {};
        observationSelectedSequence_ = 0;
        observationNextRefresh_ = 0.0;
    };
    // The UI snapshot is intentionally throttled.  A debugger reattach must
    // still invalidate it immediately so a reused PID/base cannot expose an
    // old event or selection for even one refresh interval.
    discardStaleObservation();
    const double now = ImGui::GetTime();
    if (observationNextRefresh_ == 0.0 || now >= observationNextRefresh_) {
        observation_ = ctx.debug.networkObservationSnapshot();
        discardStaleObservation();
        observationNextRefresh_ = now + (on ? 0.20 : 1.0);
    }

    ImGui::TextUnformatted("Server Watch");
    ui::SameLineIfFits(370.0f * scale);
    ImGui::TextDisabled("resolve -> connect -> request -> response / payload");
    ImGui::PushTextWrapPos();
    ImGui::TextColored(theme::col::warn(),
        "Live observation runs only against an attached process. Use it only on targets you are authorized to execute and inspect.");
    ImGui::PopTextWrapPos();

    const bool canStart = debugLive &&
        (!observationRequiresMatchingTarget_ || matchingTarget);
    ImGui::BeginDisabled(!canStart && !on);
    if (ImGui::Button(on ? "Stop Server Watch" : "Start Server Watch")) {
        if (on) ctx.debug.stopNetworkObservation();
        else    ctx.debug.startNetworkObservation();
        on = !on;
        observationNextRefresh_ = 0.0;
    }
    ImGui::EndDisabled();
    ui::SameLineIfFits(145.0f * scale);
    if (ImGui::SmallButton("Clear observation")) {
        ctx.debug.clearNetworkObservation();
        observation_ = {};
        observationSelectedSequence_ = 0;
        observationNextRefresh_ = 0.0;
    }
    if (!debugLive) {
        ImGui::PushTextWrapPos();
        ImGui::TextDisabled(observationRequiresMatchingTarget_
            ? "Launch or attach the matching target first."
            : "Attach or launch a native process first.");
        ImGui::PopTextWrapPos();
    } else if (observationRequiresMatchingTarget_ && !matchingTarget) {
        ImGui::PushTextWrapPos();
        ImGui::TextColored(theme::col::warn(),
            expectedImageActive
                ? "The attached process does not contain the matching target."
                : "The triaged document changed; reopen Live Observation from that target.");
        ImGui::PopTextWrapPos();
        if (ImGui::SmallButton("Watch attached process instead")) {
            // Explicitly leave the crackme-scoped handoff and return to the
            // ordinary Communications behavior for an arbitrary attached PID.
            observationRequiresMatchingTarget_ = false;
            observationExpectedDocument_ = {};
            observationExpectedImageGeneration_ = 0;
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("This removes the Triage target-identity guard; Server Watch still starts only when you press Start.");
    }

    const NetworkProbeCoverage& coverage = observation_.coverage;
    if (coverage.requested || on) {
        ImGui::SeparatorText("Observation coverage");
        ImGui::PushTextWrapPos();
        const ImVec4 stateColor = coverage.active ? theme::col::good() : theme::col::warn();
        ImGui::TextColored(stateColor, "%u/%u probes armed%s",
                           coverage.probesArmed, coverage.probesAvailable,
                           coverage.wow64 ? " (WOW64)" : "");
        ImGui::TextDisabled(
            "Coverage: DNS %s  Winsock %s  WinHTTP %s  WinINet %s  URLMon %s  payloads %s",
            coverage.nameResolution ? "yes" : "no",
            coverage.winsock ? "yes" : "no",
            coverage.winHttp ? "yes" : "no",
            coverage.winInet ? "yes" : "no",
            coverage.urlMon ? "yes" : "no",
            coverage.payloads ? "yes" : "no");
        ImGui::TextDisabled(
            "Probe accounting: %u skipped  %u shared with user breakpoints  %u return frames dropped",
            coverage.probesSkipped,
            coverage.probesSharedWithUserBreakpoints,
            coverage.pendingReturnsDropped);
        ImGui::TextDisabled(
            "Retention: %zu / %zu events  %llu / %zu payload bytes",
            observation_.events.size(), kNetworkObservationEventCap,
            (unsigned long long)coverage.retainedPayloadBytes,
            kNetworkObservationRetainedPayloadCap);
        if (coverage.eventsDropped || coverage.payloadBytesDropped)
            ImGui::TextColored(theme::col::warn(),
                "%u event(s) and %llu payload byte(s) dropped at the bounded retention caps",
                coverage.eventsDropped,
                (unsigned long long)coverage.payloadBytesDropped);
        if (coverage.handleStatesDropped)
            ImGui::TextColored(theme::col::warn(),
                "%u handle-lineage state record(s) dropped at the 4,096-record cap",
                coverage.handleStatesDropped);
        if (!coverage.limitations.empty() && ImGui::TreeNode("Coverage limits")) {
            for (const std::string& limitation : coverage.limitations)
                ImGui::BulletText("%s", limitation.c_str());
            ImGui::TreePop();
        }
        ImGui::PopTextWrapPos();
    }

    ImGui::SeparatorText("Observed calls");
    ImGui::SetNextItemWidth(260.0f * scale);
    ui::SearchBox("##observationfilter", "filter host / endpoint / API...",
                  observationFilter_, sizeof(observationFilter_), -1.0f);
    std::string eventNeedle = observationFilter_;
    for (char& c : eventNeedle) c = (char)std::tolower((unsigned char)c);
    std::vector<int> eventView;
    eventView.reserve(observation_.events.size());
    for (int i = (int)observation_.events.size() - 1; i >= 0; --i) {
        const NetworkObservationEvent& event = observation_.events[(size_t)i];
        if (debugLive &&
            (event.pid != debug.pid ||
             event.sessionGeneration != debug.sessionGeneration))
            continue;
        std::string hay = std::string(observationStageName(event.stage)) + ' ' +
                          observationApiName(event.api) + ' ' + event.hostname + ' ' +
                          event.ip + ' ' + event.endpoint + ' ' + event.method + ' ' +
                          event.object + ' ' + event.path + ' ' +
                          (event.portValid ? std::to_string(event.port) : std::string()) + ' ' +
                          event.detail + ' ' + observationOutcome(event);
        if (const auto contract = observationReturnContract(event.api)) {
            hay += ' '; hay += contract->successMeaning;
            hay += ' '; hay += contract->failureMeaning;
        }
        for (char& c : hay) c = (char)std::tolower((unsigned char)c);
        if (eventNeedle.empty() || hay.find(eventNeedle) != std::string::npos)
            eventView.push_back(i);
    }
    ImGui::TextDisabled("%d shown / %zu events", (int)eventView.size(), observation_.events.size());

    if (ImGui::BeginTable("server_watch_events", 6,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable,
            ImVec2(0, 230.0f * scale),
            (std::max)(ImGui::GetContentRegionAvail().x, 960.0f * scale))) {
        ImGui::TableSetupScrollFreeze(1, 1);
        ImGui::TableSetupColumn("Stage", ImGuiTableColumnFlags_WidthFixed, 78.0f * scale);
        ImGui::TableSetupColumn("API", ImGuiTableColumnFlags_WidthFixed, 155.0f * scale);
        ImGui::TableSetupColumn("Server / request");
        ImGui::TableSetupColumn("Detail");
        ImGui::TableSetupColumn("Outcome", ImGuiTableColumnFlags_WidthFixed, 135.0f * scale);
        ImGui::TableSetupColumn("Continuation", ImGuiTableColumnFlags_WidthFixed, 112.0f * scale);
        ImGui::TableHeadersRow();
        ImGuiListClipper eventClip;
        eventClip.Begin((int)eventView.size());
        while (eventClip.Step()) {
            for (int row = eventClip.DisplayStart; row < eventClip.DisplayEnd; ++row) {
                const NetworkObservationEvent& event =
                    observation_.events[(size_t)eventView[(size_t)row]];
                ImGui::TableNextRow();
                ImGui::PushID((int)event.sequence);
                ImGui::TableNextColumn();
                if (ImGui::Selectable(observationStageName(event.stage),
                                      observationSelectedSequence_ == event.sequence,
                                      ImGuiSelectableFlags_SpanAllColumns))
                    observationSelectedSequence_ = event.sequence;
                ImGui::TableNextColumn(); ImGui::TextDisabled("%s", observationApiName(event.api));
                ImGui::TableNextColumn(); ImGui::TextUnformatted(observationSummary(event).c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(event.detail.c_str());
                ImGui::TableNextColumn();
                const std::string outcome = observationOutcome(event);
                const ImVec4 outcomeColor = outcome.rfind("success", 0) == 0
                    ? theme::col::good()
                    : outcome.rfind("failure", 0) == 0 ? theme::col::bad()
                    : theme::col::muted();
                ImGui::TextColored(outcomeColor, "%s", outcome.c_str());
                ImGui::TableNextColumn();
                if (event.caller) ImGui::Text("0x%llX", (unsigned long long)event.caller);
                else              ImGui::TextDisabled("-");
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
    if (observation_.events.empty())
        ImGui::TextDisabled(on ? "Waiting for the target's networking APIs..."
                               : "Start Server Watch to capture a grounded live network trail.");

    const NetworkObservationEvent* selectedEvent = nullptr;
    for (const NetworkObservationEvent& event : observation_.events)
        if (event.sequence == observationSelectedSequence_ &&
            (!debugLive ||
             (event.pid == debug.pid &&
              event.sessionGeneration == debug.sessionGeneration))) {
            selectedEvent = &event;
            break;
        }
    if (selectedEvent) {
        ImGui::Text("%s", observationSummary(*selectedEvent).c_str());
        ImGui::SameLine(); ImGui::TextDisabled("tid %u%s", selectedEvent->tid,
                                                selectedEvent->truncated ? "  truncated" : "");
        if (const auto contract = observationReturnContract(selectedEvent->api)) {
            const std::string expected = observationContractSummary(*contract);
            const std::string outputs = observationOutputSummary(*contract);
            ImGui::TextWrapped("Expected API result: %s", expected.c_str());
            ImGui::TextWrapped("Expected reply/output fields: %s", outputs.c_str());
        } else {
            ImGui::TextDisabled("Expected API result: exact contract unavailable");
        }
        const std::string outcome = observationOutcome(*selectedEvent);
        const std::string rawResult = observationRawResultText(*selectedEvent);
        std::string observed = outcome + "; raw return " + rawResult;
        if (selectedEvent->requestedBytesValid)
            observed += "; requested " + std::to_string(selectedEvent->requestedBytes) + " byte(s)";
        if (selectedEvent->transferredValid)
            observed += "; transferred " + std::to_string(selectedEvent->transferred) + " byte(s)";
        const ImVec4 observedColor = outcome.rfind("success", 0) == 0
            ? theme::col::good()
            : outcome.rfind("failure", 0) == 0 ? theme::col::bad()
            : theme::col::warn();
        ImGui::TextColored(observedColor, "Observed: %s", observed.c_str());
        const bool selectedReplySide =
            selectedEvent->stage == NetworkObservationStage::Receive ||
            selectedEvent->stage == NetworkObservationStage::Response;
        if (selectedReplySide) {
            ImGui::TextColored(theme::col::warn(),
                "This confirms the API operation/output evidence only; it does not prove that the server accepted the license or that reply content passed validation.");
        }
        ImGui::TextDisabled("Evidence: %s%s%s", observationEvidenceName(selectedEvent->evidenceQuality),
                            selectedEvent->asyncPartial ? "  | asynchronous body is partial" : "",
                            selectedEvent->payloadOpaque ? "  | payload is opaque" : "");
        if (!selectedEvent->hostname.empty() || !selectedEvent->ip.empty() ||
            selectedEvent->portValid || !selectedEvent->path.empty()) {
            ImGui::TextDisabled("Target: host %s  ip %s  port %s  path %s",
                                selectedEvent->hostname.empty() ? "-" : selectedEvent->hostname.c_str(),
                                selectedEvent->ip.empty() ? "-" : selectedEvent->ip.c_str(),
                                selectedEvent->portValid
                                    ? std::to_string(selectedEvent->port).c_str() : "-",
                                selectedEvent->path.empty() ? "-" : selectedEvent->path.c_str());
        }
        if (!selectedEvent->runtimeModule.empty() || selectedEvent->fileOffsetValid) {
            if (selectedEvent->fileOffsetValid)
                ImGui::TextDisabled("Continuation mapping: %s + file 0x%llX",
                                    selectedEvent->runtimeModule.c_str(),
                                    (unsigned long long)selectedEvent->fileOffset);
            else
                ImGui::TextDisabled("Continuation module: %s (FILE mapping unproven)",
                                    selectedEvent->runtimeModule.c_str());
            if (!selectedEvent->mappingEvidence.empty() && ImGui::IsItemHovered())
                ImGui::SetTooltip("%s", selectedEvent->mappingEvidence.c_str());
        }
        const bool eventMatchesActiveSession =
            selectedEvent->pid == debug.pid &&
            selectedEvent->sessionGeneration == debug.sessionGeneration;
        bool eventMappingStillLoaded = false;
        if (debugLive && eventMatchesActiveSession) {
            for (const DbgModule& module : debug.modules) {
                if (NetworkObservationEventMatchesMapping(
                        *selectedEvent, debug.pid, debug.sessionGeneration,
                        module.base, module.size, module.loadGeneration)) {
                    eventMappingStillLoaded = true;
                    break;
                }
            }
        }
        if (selectedEvent->caller && eventMappingStillLoaded) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Open continuation in Live Assembly"))
                ctx.gotoAddressLive(
                    selectedEvent->caller,
                    { selectedEvent->pid, selectedEvent->sessionGeneration });
        }
        if (debugLive && eventMatchesActiveSession &&
            selectedEvent->runtimeModuleBase && !eventMappingStillLoaded)
            ImGui::TextColored(theme::col::warn(),
                "This event belongs to an unloaded or replaced module mapping; live/static navigation is disabled.");
        const DocumentRuntimeMetadata::LiveImageIdentity& activeIdentity =
            ctx.staticRuntimeMetadata().liveImage;
        const bool eventInActiveRuntimeImage = activeRuntimeImageMatches &&
            NetworkObservationEventMatchesMapping(
                *selectedEvent, debug.pid, debug.sessionGeneration,
                matchingBase, matchingSize,
                activeIdentity.moduleLoadGeneration);
        const bool mappedActiveImage = ctx.staticBinary().isMappedImage();
        if (eventInActiveRuntimeImage &&
            (mappedActiveImage || selectedEvent->fileOffsetValid)) {
            uint64_t staticContinuation = 0;
            const DocumentAnalysisCache& cache = ctx.staticAnalysisCache();
            const NetworkProbeDescriptor* descriptor =
                NetworkProbeDescriptorFor(selectedEvent->api);
            const auto exactApi = descriptor
                ? LookupNetworkApi(descriptor->dll, descriptor->symbol)
                : std::nullopt;
            NetworkReturnDisposition observedDisposition =
                NetworkReturnDisposition::Indeterminate;
            bool observedDispositionValid = false;
            if (selectedEvent->resultValid) {
                if (const auto observedContract =
                        observationReturnContract(selectedEvent->api)) {
                    observedDisposition = InterpretNetworkApiReturn(
                        *observedContract, selectedEvent->rawResult,
                        std::nullopt,
                        selectedEvent->pointerWidthBits
                            ? selectedEvent->pointerWidthBits : 64u);
                    observedDispositionValid = true;
                }
            }
            const NetworkReturnFlow* staticFlow = nullptr;
            const char* staticFlowMatchEvidence = nullptr;
            bool staticFlowExactContinuation = false;
            const CrackmeTriageReturnDecisionInput* staticStatusDecision = nullptr;
            const NetworkReplyDecisionFlow* staticReplyDecision = nullptr;
            size_t staticReplyDecisionIndex = 0;
            bool staticReplyDecisionIndexValid = false;
            bool staticReplyExactCallsite = false;
            const AuthorizationFlow* downstreamValidation = nullptr;
            size_t downstreamValidationCount = 0;
            bool staticStatusCodeValidationAvailable = false;
            bool staticStatusCodeValidated = false;
            bool staticStatusCodeMismatch = false;
            bool staticReplyCodeValidationAvailable = false;
            bool staticReplyCodeValidated = false;
            bool staticReplyCodeMismatch = false;
            bool staticContinuationValid = false;
            if (mappedActiveImage) {
                // A live-memory BinaryFile stores mapped layout (section raw
                // offsets are RVAs), while NetworkObservationEvent::fileOffset
                // is an original-PE raw offset projected from remote headers.
                // The exact runtime caller is therefore the authoritative
                // address for an exact-session mapped document.
                staticContinuation = selectedEvent->caller;
                size_t available = 0;
                staticContinuationValid =
                    ctx.staticBinary().ptrFromVA(staticContinuation, available) &&
                    available != 0;
            } else {
                staticContinuationValid = ctx.staticBinary().offsetToVA(
                    selectedEvent->fileOffset, staticContinuation);
            }
            if (cache.crackmeTriage && exactApi && staticContinuationValid) {
                for (const NetworkReturnFlow& candidate :
                     cache.crackmeTriage->returnFlows) {
                    if (!candidate.apiIndexValid ||
                        candidate.apiIndex >= cache.crackmeTriage->apis.size())
                        continue;
                    const CrackmeTriageApiEvidence& api =
                        cache.crackmeTriage->apis[candidate.apiIndex];
                    if (api.dll != exactApi->dll ||
                        api.canonicalName != exactApi->canonicalName)
                        continue;
                    const bool exactContinuation = mappedActiveImage
                        ? candidate.continuationAddressValid &&
                          candidate.continuationAddress == staticContinuation
                        : candidate.continuationFileOffsetValid &&
                          candidate.continuationFileOffset ==
                              selectedEvent->fileOffset;
                    const bool continuationIsUse =
                        candidate.useAddressValid &&
                        candidate.useAddress == staticContinuation;
                    const bool followsCallsite =
                        candidate.callsiteValid &&
                        staticContinuation > candidate.callsite &&
                        staticContinuation - candidate.callsite <= 16;
                    if (exactContinuation) {
                        staticFlow = &candidate;
                        staticFlowExactContinuation = true;
                        staticFlowMatchEvidence =
                            "exact API return continuation";
                        break;
                    }
                    if (!staticFlow && (continuationIsUse || followsCallsite)) {
                        staticFlow = &candidate;
                        staticFlowMatchEvidence = continuationIsUse
                            ? "heuristic same-API use at the observed continuation"
                            : "heuristic same-API callsite within 16 bytes of the observed continuation";
                    }
                }

                if (staticFlow) {
                    float bestStatusScore = -1.0f;
                    for (const CrackmeTriageReturnDecisionInput& decision :
                         staticFlow->decisions) {
                        float score = decision.confidence +
                            static_cast<float>(decision.hops.size()) * 0.001f;
                        if (observedDispositionValid &&
                            observedDisposition ==
                                NetworkReturnDisposition::Failure &&
                            decision.failureAddressValid)
                            score += 10.0f;
                        else if (observedDispositionValid &&
                                 observedDisposition ==
                                     NetworkReturnDisposition::Success &&
                                 decision.successAddressValid)
                            score += 10.0f;
                        if (!staticStatusDecision || score > bestStatusScore) {
                            bestStatusScore = score;
                            staticStatusDecision = &decision;
                        }
                    }
                }

                uint64_t continuationOwner = 0;
                bool continuationOwnerValid = false;
                if (cache.functions) {
                    for (const FuncResult& function : *cache.functions) {
                        const uint64_t end = function.address + function.size;
                        if (staticContinuation >= function.address &&
                            end >= function.address &&
                            staticContinuation < end) {
                            continuationOwner = function.address;
                            continuationOwnerValid = true;
                            break;
                        }
                    }
                }
                int bestReplyScore = -1;
                for (size_t candidateIndex = 0;
                     candidateIndex < cache.crackmeTriage->replyDecisionFlows.size();
                     ++candidateIndex) {
                    const NetworkReplyDecisionFlow& candidate =
                        cache.crackmeTriage->replyDecisionFlows[candidateIndex];
                    if (!candidate.apiIndexValid ||
                        candidate.apiIndex >= cache.crackmeTriage->apis.size() ||
                        !candidate.comparisonAddressValid)
                        continue;
                    const CrackmeTriageApiEvidence& api =
                        cache.crackmeTriage->apis[candidate.apiIndex];
                    const bool sameApi = api.dll == exactApi->dll &&
                        api.canonicalName == exactApi->canonicalName;
                    const bool continuationIsComparison =
                        candidate.comparisonAddress == staticContinuation ||
                        (candidate.decisionAddressValid &&
                         candidate.decisionAddress == staticContinuation);
                    const bool followsCallsite = candidate.callsiteValid &&
                        staticContinuation > candidate.callsite &&
                        staticContinuation - candidate.callsite <= 16;
                    const bool sameOwner = continuationOwnerValid &&
                        candidate.functionAddressValid &&
                        candidate.functionAddress == continuationOwner;
                    const bool sameObservedStaticCall = staticFlow &&
                        staticFlow->callsiteValid && candidate.callsiteValid &&
                        candidate.callsite == staticFlow->callsite;
                    int score = -1;
                    if (sameApi && sameObservedStaticCall)
                        score = 8;
                    else if (sameApi &&
                             (continuationIsComparison || followsCallsite))
                        score = 5;
                    else if (sameApi && sameOwner)
                        score = 4;
                    if (score < 0) continue;
                    if (candidate.decisionAddressValid) ++score;
                    if (score > bestReplyScore) {
                        bestReplyScore = score;
                        staticReplyDecision = &candidate;
                        staticReplyDecisionIndex = candidateIndex;
                        staticReplyDecisionIndexValid = true;
                    }
                }
                staticReplyExactCallsite = staticReplyDecision && staticFlow &&
                    staticReplyDecision->callsiteValid &&
                    staticFlow->callsiteValid &&
                    staticReplyDecision->callsite == staticFlow->callsite;
                if (staticReplyDecisionIndexValid) {
                    for (const AuthorizationFlow& flow :
                         cache.crackmeTriage->authorization.flows) {
                        if (!flow.networkReplyFlowIndexValid ||
                            flow.networkReplyFlowIndex != staticReplyDecisionIndex)
                            continue;
                        if (!downstreamValidation) downstreamValidation = &flow;
                        ++downstreamValidationCount;
                    }
                }
            }
            if (staticFlowExactContinuation && staticFlow &&
                debug.state == DbgState::Paused) {
                auto liveSignatureMatches = [&](uint64_t runtimeAddress,
                                                const CodeByteSignature& signature,
                                                bool& available) {
                    available = false;
                    if (!runtimeAddress || !ValidCodeByteSignature(signature))
                        return false;
                    std::array<uint8_t, kCodeByteSignatureMax> live{};
                    const size_t got = ctx.debug.readMemoryMaskedForSession(
                        debug.pid, debug.sessionGeneration, runtimeAddress,
                        live.data(), signature.length);
                    available = got == signature.length;
                    return available && CodeByteSignatureMatches(
                        signature, live.data(), got);
                };
                auto staticSignatureMatches = [&](uint64_t staticAddress,
                                                  bool addressValid,
                                                  const CodeByteSignature& signature,
                                                  bool& available) {
                    available = false;
                    uint64_t runtimeAddress = 0;
                    if (!addressValid || !ctx.debuggerStaticRuntimeVA(
                            debug, staticAddress, runtimeAddress))
                        return false;
                    return liveSignatureMatches(runtimeAddress, signature,
                                                available);
                };

                bool continuationAvailable = false;
                bool comparisonAvailable = false;
                bool branchAvailable = false;
                const bool continuationMatches = liveSignatureMatches(
                    selectedEvent->caller, staticFlow->continuationSignature,
                    continuationAvailable);
                if (staticStatusDecision) {
                    const bool comparisonMatches = staticSignatureMatches(
                        staticStatusDecision->comparisonAddress,
                        staticStatusDecision->comparisonAddressValid,
                        staticStatusDecision->comparisonSignature,
                        comparisonAvailable);
                    const bool branchMatches = staticSignatureMatches(
                        staticStatusDecision->decisionAddress,
                        staticStatusDecision->decisionAddressValid,
                        staticStatusDecision->decisionSignature,
                        branchAvailable);
                    staticStatusCodeValidationAvailable =
                        continuationAvailable && comparisonAvailable &&
                        branchAvailable;
                    staticStatusCodeValidated =
                        staticStatusCodeValidationAvailable &&
                        continuationMatches && comparisonMatches && branchMatches;
                    staticStatusCodeMismatch =
                        staticStatusCodeValidationAvailable &&
                        !staticStatusCodeValidated;
                }
                if (staticReplyDecision && staticReplyExactCallsite) {
                    comparisonAvailable = false;
                    branchAvailable = false;
                    const bool comparisonMatches = staticSignatureMatches(
                        staticReplyDecision->comparisonAddress,
                        staticReplyDecision->comparisonAddressValid,
                        staticReplyDecision->comparisonSignature,
                        comparisonAvailable);
                    const bool branchMatches = staticSignatureMatches(
                        staticReplyDecision->decisionAddress,
                        staticReplyDecision->decisionAddressValid,
                        staticReplyDecision->decisionSignature,
                        branchAvailable);
                    staticReplyCodeValidationAvailable =
                        continuationAvailable && comparisonAvailable &&
                        branchAvailable;
                    staticReplyCodeValidated =
                        staticReplyCodeValidationAvailable &&
                        continuationMatches && comparisonMatches && branchMatches;
                    staticReplyCodeMismatch =
                        staticReplyCodeValidationAvailable &&
                        !staticReplyCodeValidated;
                }
            }
            if (staticFlow) {
                ImGui::TextColored(staticFlowExactContinuation
                        ? theme::col::good() : theme::col::warn(),
                    "Live/static address match: %s",
                    staticFlowMatchEvidence ? staticFlowMatchEvidence
                                            : "unclassified static candidate");
                if (!staticFlowExactContinuation)
                    ImGui::TextDisabled(
                        "The exact continuation record was unavailable. Comparison/branch links are heuristic review leads; arm prediction is disabled.");
                else if (debug.state != DbgState::Paused)
                    ImGui::TextColored(theme::col::warn(),
                        "Pause the target to validate the live continuation, comparison, and branch instructions. Static arm prediction is disabled while it runs.");
                else if (staticStatusDecision && staticStatusCodeValidated)
                    ImGui::TextColored(theme::col::good(),
                        "Current live continuation, comparison, and branch instruction bytes exactly match this static lineage. For on-disk images, relocation-overlapping instructions are unavailable rather than wildcarded." );
                else if (staticStatusDecision && staticStatusCodeMismatch)
                    ImGui::TextColored(theme::col::warn(),
                        "Current live instruction bytes differ from the analyzed continuation/comparison/branch. The static lineage remains a review lead; arm prediction is disabled.");
                else if (staticStatusDecision &&
                         !staticStatusCodeValidationAvailable)
                    ImGui::TextColored(theme::col::warn(),
                        "A complete live/static instruction-byte comparison is unavailable. The static lineage remains a review lead; arm prediction is disabled.");
                std::string staticHandling;
                if (!staticFlow->decisions.empty()) {
                    staticHandling = "traced through " + std::to_string(
                        staticStatusDecision ? staticStatusDecision->hops.size() : 0) +
                        " provenance hop(s) to a comparison branch";
                } else if (staticFlow->returnValueUseKnown) {
                    staticHandling = staticFlow->useSummary.empty()
                        ? NetworkReturnUseKindText(staticFlow->useKind)
                        : staticFlow->useSummary;
                } else if (staticFlow->lineageAnalysisAttempted) {
                    staticHandling = staticFlow->lineageComplete
                        ? "bounded scalar lineage found no terminal comparison"
                        : "bounded scalar lineage is partial";
                } else {
                    staticHandling = "use not recovered inside the annotation window";
                }
                ImGui::TextWrapped("Static caller handling (%s): %s",
                    staticFlow->decisions.empty()
                        ? "bounded first use" : "bounded multi-hop provenance",
                    staticHandling.c_str());
                if (!staticFlow->honestyLabel.empty() && ImGui::IsItemHovered())
                    ImGui::SetTooltip("%s", staticFlow->honestyLabel.c_str());
                if (staticFlow->callsiteValid) {
                    if (ImGui::SmallButton("Open static call"))
                        ctx.gotoAddress(staticFlow->callsite);
                }
                if (staticFlow->useAddressValid) {
                    if (staticFlow->callsiteValid) ImGui::SameLine();
                    if (ImGui::SmallButton("Open static use"))
                        ctx.gotoAddress(staticFlow->useAddress);
                }
                if (staticFlow->decisionAddressValid) {
                    if (staticFlow->callsiteValid || staticFlow->useAddressValid)
                        ImGui::SameLine();
                    if (ImGui::SmallButton("Open static decision"))
                        ctx.gotoAddress(staticFlow->decisionAddress);
                }
                if (staticStatusDecision) {
                    ImGui::SeparatorText("Static transport-status prediction");
                    ImGui::TextWrapped("%s%s%s",
                        staticStatusDecision->predicate.empty()
                            ? "network API return is checked"
                            : staticStatusDecision->predicate.c_str(),
                        staticStatusDecision->expectedValue.empty()
                            ? "" : " against ",
                        staticStatusDecision->expectedValue.c_str());
                    ImGui::TextDisabled("Taken: %s  |  fallthrough: %s  |  %zu provenance hop%s",
                        NetworkReturnDispositionText(
                            staticStatusDecision->takenDisposition),
                        NetworkReturnDispositionText(
                            staticStatusDecision->fallthroughDisposition),
                        staticStatusDecision->hops.size(),
                        staticStatusDecision->hops.size() == 1 ? "" : "s");
                    ImGui::TextDisabled(
                        "Server Watch observed the API return only. The comparison, branch, and arm below are static lineage; downstream execution was not observed.");
                    if (staticStatusDecision->comparisonAddressValid &&
                        ImGui::SmallButton("Open static status comparison"))
                        ctx.gotoAddress(staticStatusDecision->comparisonAddress);
                    if (staticStatusDecision->decisionAddressValid) {
                        if (staticStatusDecision->comparisonAddressValid)
                            ImGui::SameLine();
                        if (ImGui::SmallButton("Open static status branch"))
                            ctx.gotoAddress(staticStatusDecision->decisionAddress);
                    }
                    if (staticStatusCodeValidated && observedDispositionValid &&
                        observedDisposition == NetworkReturnDisposition::Failure &&
                        staticStatusDecision->failureAddressValid) {
                        if (staticStatusDecision->comparisonAddressValid ||
                            staticStatusDecision->decisionAddressValid)
                            ImGui::SameLine();
                        if (ImGui::SmallButton("Open predicted failure arm"))
                            ctx.gotoAddress(staticStatusDecision->failureAddress);
                    } else if (staticStatusCodeValidated && observedDispositionValid &&
                               observedDisposition == NetworkReturnDisposition::Success &&
                               staticStatusDecision->successAddressValid) {
                        if (staticStatusDecision->comparisonAddressValid ||
                            staticStatusDecision->decisionAddressValid)
                            ImGui::SameLine();
                        if (ImGui::SmallButton("Open predicted success arm"))
                            ctx.gotoAddress(staticStatusDecision->successAddress);
                    } else if (staticStatusCodeValidated && observedDispositionValid &&
                               observedDisposition ==
                               NetworkReturnDisposition::Indeterminate) {
                        ImGui::TextColored(theme::col::warn(),
                            "The observed sentinel may be asynchronous/pending; no static arm is predicted without decisive error/completion state.");
                    }
                    if (!staticStatusDecision->hops.empty() &&
                        ImGui::TreeNode("##live_status_provenance",
                            "Full status provenance (%zu hop%s)",
                            staticStatusDecision->hops.size(),
                            staticStatusDecision->hops.size() == 1 ? "" : "s")) {
                        for (size_t hopIndex = 0;
                             hopIndex < staticStatusDecision->hops.size();
                             ++hopIndex) {
                            const ValueProvenanceHop& hop =
                                staticStatusDecision->hops[hopIndex];
                            ImGui::PushID(static_cast<int>(hopIndex));
                            if (hop.addressValid) {
                                char label[48];
                                std::snprintf(label, sizeof(label), "0x%llX",
                                    (unsigned long long)hop.address);
                                if (ImGui::SmallButton(label))
                                    ctx.gotoAddress(hop.address);
                                ImGui::SameLine();
                            }
                            ImGui::TextWrapped("%s%s%s%s%s",
                                ValueProvenanceHopKindText(hop.kind),
                                hop.functionName.empty() ? "" : " in ",
                                hop.functionName.c_str(),
                                hop.instruction.empty() ? "" : ": ",
                                hop.instruction.c_str());
                            if (ImGui::IsItemHovered() && !hop.evidence.empty())
                                ImGui::SetTooltip("%s", hop.evidence.c_str());
                            ImGui::PopID();
                        }
                        ImGui::TreePop();
                    }
                    if (!staticFlow->lineageComplete &&
                        !staticFlow->lineageIncompleteReason.empty())
                        ImGui::TextColored(theme::col::warn(),
                            "Static lineage is partial: %s",
                            staticFlow->lineageIncompleteReason.c_str());
                }
            } else {
                ImGui::TextDisabled(
                    "Static caller handling was not matched to this continuation in the current bounded FILE report.");
            }
            if (selectedReplySide) {
                ImGui::SeparatorText("Static reply-content comparison lead");
                if (staticReplyDecision) {
                    ImGui::TextWrapped("%s",
                        staticReplyDecision->comparisonSummary.empty()
                            ? staticReplyDecision->comparisonInstruction.c_str()
                            : staticReplyDecision->comparisonSummary.c_str());
                    if (!staticReplyDecision->expectedValue.empty())
                        ImGui::TextColored(theme::col::accent(),
                            "Expected/other operand: %s",
                            staticReplyDecision->expectedValue.c_str());
                    ImGui::TextDisabled(
                        "Match/mismatch is proven only for this comparison. The live event does not prove either path executed or that either path means business acceptance.");
                    if (!staticFlowExactContinuation ||
                        !staticReplyExactCallsite)
                        ImGui::TextColored(theme::col::warn(),
                            "No exact observed-callsite/API-return continuation was matched. Match/mismatch path navigation is disabled; these are heuristic static review leads.");
                    else if (debug.state != DbgState::Paused)
                        ImGui::TextColored(theme::col::warn(),
                            "Pause the target to validate the live continuation, reply comparison, and branch instructions before opening a match/mismatch path.");
                    else if (staticReplyCodeValidated)
                        ImGui::TextColored(theme::col::good(),
                            "Current live continuation, reply comparison, and branch instruction bytes exactly match this static lineage. For on-disk images, relocation-overlapping instructions are unavailable rather than wildcarded." );
                    else if (staticReplyCodeMismatch)
                        ImGui::TextColored(theme::col::warn(),
                            "Current live bytes differ from the analyzed continuation/reply comparison/branch. Match/mismatch path navigation is disabled.");
                    else if (!staticReplyCodeValidationAvailable)
                        ImGui::TextColored(theme::col::warn(),
                            "A complete live/static continuation/reply comparison/branch byte check is unavailable. Match/mismatch path navigation is disabled.");
                    if (staticReplyDecision->comparisonAddressValid &&
                        ImGui::SmallButton("Open reply comparison"))
                        ctx.gotoAddress(staticReplyDecision->comparisonAddress);
                    if (staticReplyDecision->decisionAddressValid) {
                        if (staticReplyDecision->comparisonAddressValid)
                            ImGui::SameLine();
                        if (ImGui::SmallButton("Open comparison branch"))
                            ctx.gotoAddress(staticReplyDecision->decisionAddress);
                    }
                    if (staticReplyDecision->matchAddressValid) {
                        if (staticReplyDecision->comparisonAddressValid ||
                            staticReplyDecision->decisionAddressValid)
                            ImGui::SameLine();
                        ImGui::BeginDisabled(!staticReplyCodeValidated);
                        if (ImGui::SmallButton("Open match path"))
                            ctx.gotoAddress(staticReplyDecision->matchAddress);
                        ImGui::EndDisabled();
                        if (ImGui::IsItemHovered(
                                ImGuiHoveredFlags_AllowWhenDisabled) &&
                            !staticReplyDecision->takenPathSummary.empty())
                            ImGui::SetTooltip("%s",
                                (staticReplyDecision->matchAddress ==
                                     staticReplyDecision->decisionTarget
                                     ? staticReplyDecision->takenPathSummary
                                     : staticReplyDecision->fallthroughPathSummary)
                                    .c_str());
                    }
                    if (staticReplyDecision->mismatchAddressValid) {
                        if (staticReplyDecision->comparisonAddressValid ||
                            staticReplyDecision->decisionAddressValid ||
                            staticReplyDecision->matchAddressValid)
                            ImGui::SameLine();
                        ImGui::BeginDisabled(!staticReplyCodeValidated);
                        if (ImGui::SmallButton("Open mismatch path"))
                            ctx.gotoAddress(staticReplyDecision->mismatchAddress);
                        ImGui::EndDisabled();
                        if (ImGui::IsItemHovered(
                                ImGuiHoveredFlags_AllowWhenDisabled) &&
                            !staticReplyDecision->takenPathSummary.empty())
                            ImGui::SetTooltip("%s",
                                (staticReplyDecision->mismatchAddress ==
                                     staticReplyDecision->decisionTarget
                                     ? staticReplyDecision->takenPathSummary
                                     : staticReplyDecision->fallthroughPathSummary)
                                    .c_str());
                    }
                    if (!staticReplyDecision->evidence.empty())
                        ImGui::TextWrapped("Static evidence: %s",
                            staticReplyDecision->evidence.c_str());
                    if (downstreamValidation) {
                        if (ImGui::SmallButton("Open downstream validation"))
                            ctx.openCrackmeAuthorization(downstreamValidation->id);
                        ImGui::SameLine();
                        ImGui::TextDisabled(
                            "%zu linked allow/deny flow%s; includes remembered-state and startup gates when proven",
                            downstreamValidationCount,
                            downstreamValidationCount == 1 ? "" : "s");
                    }
                } else {
                    ImGui::TextColored(theme::col::warn(),
                        "No reply-buffer comparison was matched to this continuation in the bounded FILE report. Follow the payload/header output from the receive API; the API-result branch above is only status handling.");
                }
            }
        }
        if (!selectedEvent->payload.empty() && ImGui::TreeNode("Observed payload")) {
            std::string body = (capHex_ || !mostlyText(selectedEvent->payload))
                             ? toHexDump(selectedEvent->payload)
                             : toText(selectedEvent->payload);
            ui::PushMono();
            ImGui::InputTextMultiline("##observationpayload", body.data(), body.size() + 1,
                                      ImVec2(-1, 100.0f * scale), ImGuiInputTextFlags_ReadOnly);
            ui::PopMono();
            ImGui::TreePop();
        }
    }

    ImGui::SeparatorText("Observation log");
    ImGui::Checkbox("Display selected payload as hex##caps", &capHex_);
    ImGui::SameLine();
    const bool logging = ctx.debug.netCaptureLogEnabled();
    // Starting a file log is also an observation start edge. Apply the same
    // attachment/document identity guard as the visible Start Server Watch
    // button so a routed Triage watch cannot be redirected through this path.
    ImGui::BeginDisabled(!logging && !on && !canStart);
    if (ImGui::SmallButton(logging ? "Stop file log##caps" : "Start file log...##caps")) {
        if (logging) {
            ctx.debug.closeNetCaptureLogFile();
            capLogStatus_ = "Finishing queued network log records...";
            ui::Toast(ui::ToastKind::Info, capLogStatus_);
        } else {
            std::string path;
            if (choosePayloadLogFile(path)) {
                // The save dialog is blocking, so revalidate after it closes:
                // the process may have exited/re-attached or the source document
                // may have changed while the picker was open.
                const DbgSnapshot current = ctx.debug.snapshot();
                const bool expectedStillActive = observationRequiresMatchingTarget_ &&
                    ctx.staticDocumentId() == observationExpectedDocument_ &&
                    ctx.staticImageGeneration() == observationExpectedImageGeneration_;
                uint64_t currentBase = 0, currentSize = 0;
                const bool currentMatchingTarget = expectedStillActive &&
                    ctx.debuggerRuntimeImage(current, currentBase, currentSize);
                const bool currentLive = current.state == DbgState::Running ||
                                         current.state == DbgState::Paused;
                const bool mayStartNow = currentLive &&
                    (!observationRequiresMatchingTarget_ || currentMatchingTarget);
                if (!mayStartNow) {
                    capLogStatus_ = observationRequiresMatchingTarget_
                        ? "Log start cancelled: attach the matching triaged target first."
                        : "Log start cancelled: the debug target is no longer attached.";
                    ui::Toast(ui::ToastKind::Warn, capLogStatus_);
                } else {
                    std::string err;
                    if (ctx.debug.setNetCaptureLogFile(path, /*append=*/false, &err)) {
                        if (!on) ctx.debug.startNetworkObservation();
                        if (!ctx.debug.netTapEnabled()) {
                            // Core performs its own live-state check. If the
                            // process exited in the narrow interval after our
                            // post-picker snapshot, close the just-opened file
                            // instead of reporting an observation that did not
                            // actually start.
                            ctx.debug.closeNetCaptureLogFile();
                            on = false;
                            capLogStatus_ =
                                "Log start cancelled: the debug target ended before Server Watch could start.";
                            ui::Toast(ui::ToastKind::Warn, capLogStatus_);
                        } else {
                            on = true;
                            capLogStatus_ = "Opening network payload log: " + path;
                            ui::Toast(ui::ToastKind::Info, "Network payload log requested");
                        }
                    } else {
                        capLogStatus_ = "Log start failed: " + err;
                        ui::Toast(ui::ToastKind::Error, capLogStatus_);
                    }
                }
            }
        }
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Queue captured buffers for a background text/hex writer. Queue drops and storage errors are shown below.");
    const auto logStatus = ctx.debug.netCaptureLogStatus();
    if (!logStatus.enabled && !logStatus.draining &&
        capLogStatus_ == "Finishing queued network log records...")
        capLogStatus_ = "Network payload log stopped.";
    if (ctx.debug.netCaptureLogEnabled()) {
        std::string path = ctx.debug.netCaptureLogPath();
        ImGui::TextColored(logStatus.opening ? theme::col::warn() : theme::col::good(), "%s",
            logStatus.opening ? "Opening log file..." : "Logging to file");
        if (!path.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", path.c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy path##caplog")) ImGui::SetClipboardText(path.c_str());
        }
    } else if (logStatus.draining) {
        ImGui::TextDisabled("Finishing queued records and closing log file...");
    } else if (!capLogStatus_.empty() && logStatus.error.empty()) {
        ImGui::TextDisabled("%s", capLogStatus_.c_str());
    }
    if (!logStatus.error.empty()) {
        ImGui::TextColored(theme::col::bad(), "%s", logStatus.error.c_str());
    }
    if (logStatus.queuedRecords || logStatus.droppedRecords) {
        ImGui::TextDisabled("Writer queue: %zu records (%zu KiB); %llu dropped",
            logStatus.queuedRecords, logStatus.queuedBytes / 1024,
            static_cast<unsigned long long>(logStatus.droppedRecords));
    }
    if (logStatus.opening || logStatus.draining || logStatus.queuedRecords)
        ctx.wantContinuousRedraw = true;
    if (!on) {
        ImGui::TextDisabled(
            "Server Watch follows exact Winsock, WinHTTP, and WinINet calls, including handle lineage and WOW64 targets where probes are available.");
        ImGui::TextDisabled(
            "Plaintext request/response buffers are readable; custom TLS and encrypted transport payloads remain ciphertext. Coverage limits are reported above.");
        return;
    }
    ctx.wantContinuousRedraw = true;   // stream captures live
}

} // namespace ds
