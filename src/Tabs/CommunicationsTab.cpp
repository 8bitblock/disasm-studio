#include "CommunicationsTab.h"
// Winsock headers must precede windows.h; iphlpapi gives the per-PID conn tables.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "../Core/JvmAttach.h"
#include "../Core/NetworkEndpoint.h"
#include "../Core/GameMakerArchive.h"
#include "../Disasm/JvmDisassembler.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "../Ui/Splitter.h"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <exception>
#include <new>
#include <utility>

namespace ds {

CommunicationsTab::CommunicationsTab() {
    connWorker_ = std::jthread([this](std::stop_token stop) {
        connectionWorkerLoop(stop);
    });
}

CommunicationsTab::~CommunicationsTab() {
    desiredConnEpoch_.fetch_add(1, std::memory_order_acq_rel);
    {
        std::lock_guard lock(connWorkerMutex_);
        pendingConnJob_.reset();
        readyConnResult_.reset();
    }
    connWorker_.request_stop();
    connWorkerCv_.notify_all();
    if (connWorker_.joinable()) connWorker_.join();
}

static const char* tcpStateName(unsigned long s) {
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
static DWORD fetchIpTableBounded(Fetch&& fetch, std::vector<uint8_t>& buffer) {
    constexpr DWORD kMaxTableBytes = 64u * 1024u * 1024u;
    DWORD size = 0;
    DWORD rc = fetch(nullptr, &size);
    if (rc == NO_ERROR && !size) { buffer.clear(); return NO_ERROR; }
    if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) return rc;
    for (int attempt = 0; size && attempt < 3; ++attempt) {
        if (size > kMaxTableBytes) return ERROR_NOT_ENOUGH_MEMORY;
        try { buffer.assign(size, 0); }
        catch (const std::bad_alloc&) { return ERROR_NOT_ENOUGH_MEMORY; }
        rc = fetch(buffer.data(), &size);
        if (rc == NO_ERROR) return NO_ERROR;
        if (rc != ERROR_INSUFFICIENT_BUFFER) return rc;
    }
    return rc == NO_ERROR ? ERROR_INSUFFICIENT_BUFFER : rc;
}

template <typename Table, typename Row>
static size_t boundedTableRows(const std::vector<uint8_t>& buffer, const Table* table) {
    constexpr size_t header = offsetof(Table, table);
    if (!table || buffer.size() < header) return 0;
    return std::min<size_t>(table->dwNumEntries, (buffer.size() - header) / sizeof(Row));
}

// Enumerate IPv4 + IPv6 TCP/UDP endpoints owned by `job.pid` (IP Helper API).
// This function is worker-only: it owns every allocation and publishes one
// immutable result back to the render thread.
CommunicationsTab::ConnResult
CommunicationsTab::collectConnections(const ConnJob& job) {
    ConnResult result;
    result.epoch = job.epoch;
    result.pid = job.pid;
    if (!job.pid) return result;

    // Each of the four tables uses a bounded size/fetch/retry path. A table can
    // grow between calls; successful families remain visible if another fails.
    std::vector<uint8_t> buf;
    auto failure = [&](const char* table, DWORD error) {
        if (!result.status.empty()) result.status += "; ";
        result.status += table;
        result.status += " error ";
        result.status += std::to_string(error);
    };
    auto addTcp = [&](std::string local, std::string remote, DWORD state, bool ipv6) {
        if (state == MIB_TCP_STATE_LISTEN) remote = "*";
        result.connections.push_back({std::move(local), std::move(remote), "TCP",
                                      ipv6 ? "IPv6" : "IPv4", tcpStateName(state), ipv6});
    };
    auto addUdp = [&](std::string local, bool ipv6) {
        result.connections.push_back({std::move(local), "*", "UDP",
                                      ipv6 ? "IPv6" : "IPv4", "LISTEN", ipv6});
    };

    DWORD rc = fetchIpTableBounded([&](void* data, DWORD* size) {
        return GetExtendedTcpTable(data, size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    }, buf);
    if (rc == NO_ERROR) {
        const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
        const size_t rows = boundedTableRows<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(buf, table);
        for (size_t i = 0; i < rows; ++i) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != job.pid) continue;
            addTcp(FormatIpv4Endpoint(reinterpret_cast<const uint8_t*>(&row.dwLocalAddr),
                                      (uint16_t)ntohs((u_short)row.dwLocalPort)),
                   FormatIpv4Endpoint(reinterpret_cast<const uint8_t*>(&row.dwRemoteAddr),
                                      (uint16_t)ntohs((u_short)row.dwRemotePort)),
                   row.dwState, false);
        }
    } else failure("TCP/IPv4", rc);

    rc = fetchIpTableBounded([&](void* data, DWORD* size) {
        return GetExtendedTcpTable(data, size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    }, buf);
    if (rc == NO_ERROR) {
        const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buf.data());
        const size_t rows = boundedTableRows<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(buf, table);
        for (size_t i = 0; i < rows; ++i) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != job.pid) continue;
            addTcp(FormatIpv6Endpoint(row.ucLocalAddr, (uint16_t)ntohs((u_short)row.dwLocalPort),
                                      row.dwLocalScopeId),
                   FormatIpv6Endpoint(row.ucRemoteAddr, (uint16_t)ntohs((u_short)row.dwRemotePort),
                                      row.dwRemoteScopeId),
                   row.dwState, true);
        }
    } else failure("TCP/IPv6", rc);

    rc = fetchIpTableBounded([&](void* data, DWORD* size) {
        return GetExtendedUdpTable(data, size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    }, buf);
    if (rc == NO_ERROR) {
        const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf.data());
        const size_t rows = boundedTableRows<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(buf, table);
        for (size_t i = 0; i < rows; ++i) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != job.pid) continue;
            addUdp(FormatIpv4Endpoint(reinterpret_cast<const uint8_t*>(&row.dwLocalAddr),
                                      (uint16_t)ntohs((u_short)row.dwLocalPort)), false);
        }
    } else failure("UDP/IPv4", rc);

    rc = fetchIpTableBounded([&](void* data, DWORD* size) {
        return GetExtendedUdpTable(data, size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    }, buf);
    if (rc == NO_ERROR) {
        const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buf.data());
        const size_t rows = boundedTableRows<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(buf, table);
        for (size_t i = 0; i < rows; ++i) {
            const auto& row = table->table[i];
            if (row.dwOwningPid != job.pid) continue;
            addUdp(FormatIpv6Endpoint(row.ucLocalAddr, (uint16_t)ntohs((u_short)row.dwLocalPort),
                                      row.dwLocalScopeId), true);
        }
    } else failure("UDP/IPv6", rc);

    std::sort(result.connections.begin(), result.connections.end(),
              [](const Conn& a, const Conn& b) {
        if (a.protocol != b.protocol) return a.protocol < b.protocol;
        if (a.ipv6 != b.ipv6) return a.ipv6 < b.ipv6;
        if (a.local != b.local) return a.local < b.local;
        if (a.remote != b.remote) return a.remote < b.remote;
        return a.state < b.state;
    });
    return result;
}

void CommunicationsTab::requestConnectionRefresh(uint32_t pid) {
    const uint64_t epoch = desiredConnEpoch_.fetch_add(1, std::memory_order_acq_rel) + 1;
    connsRequestedPid_ = pid;
    if (!pid) {
        std::lock_guard lock(connWorkerMutex_);
        pendingConnJob_.reset();
        readyConnResult_.reset();
        conns_.clear();
        connStatus_.clear();
        connsForPid_ = 0;
        connRefreshRunning_.store(false, std::memory_order_release);
        return;
    }
    {
        std::lock_guard lock(connWorkerMutex_);
        pendingConnJob_ = ConnJob{epoch, pid}; // latest selected process wins
        readyConnResult_.reset();
        connRefreshRunning_.store(true, std::memory_order_release);
    }
    connWorkerCv_.notify_one();
}

void CommunicationsTab::pumpConnectionRefresh() {
    std::optional<ConnResult> ready;
    {
        std::lock_guard lock(connWorkerMutex_);
        if (readyConnResult_) {
            ready = std::move(readyConnResult_);
            readyConnResult_.reset();
        }
    }
    if (!ready || ready->epoch != desiredConnEpoch_.load(std::memory_order_acquire) ||
        ready->pid != connsRequestedPid_)
        return;
    conns_ = std::move(ready->connections);
    connStatus_ = std::move(ready->status);
    connsForPid_ = ready->pid;
    connRefreshRunning_.store(false, std::memory_order_release);
}

void CommunicationsTab::connectionWorkerLoop(std::stop_token stop) {
    for (;;) {
        ConnJob job;
        {
            std::unique_lock lock(connWorkerMutex_);
            connWorkerCv_.wait(lock, [&] {
                return stop.stop_requested() || pendingConnJob_.has_value();
            });
            if (stop.stop_requested()) return;
            job = *pendingConnJob_;
            pendingConnJob_.reset();
        }

        ConnResult result;
        try {
            result = collectConnections(job);
        } catch (const std::exception& error) {
            result.epoch = job.epoch;
            result.pid = job.pid;
            result.status = std::string("connection refresh failed: ") + error.what();
        } catch (...) {
            result.epoch = job.epoch;
            result.pid = job.pid;
            result.status = "connection refresh failed: unknown worker error";
        }
        if (stop.stop_requested() ||
            desiredConnEpoch_.load(std::memory_order_acquire) != job.epoch)
            continue;
        {
            std::lock_guard lock(connWorkerMutex_);
            if (desiredConnEpoch_.load(std::memory_order_acquire) != job.epoch)
                continue;
            readyConnResult_ = std::move(result);
        }
    }
}

void CommunicationsTab::refreshProcesses() {
    // The selection follows the PID, not the row index: re-enumerating + re-sorting
    // must not move module/connection actions to a different process.
    const uint32_t prevPid = (selProc_ >= 0 && selProc_ < (int)procs_.size()) ? procs_[selProc_].pid : 0;
    procs_ = pm_.enumerate();
    enumerated_ = true;
    std::sort(procs_.begin(), procs_.end(),
              [](const ProcessInfo& a, const ProcessInfo& b) {
                  const int byName = _stricmp(a.name.c_str(), b.name.c_str());
                  return byName == 0 ? a.pid < b.pid : byName < 0;
              });
    selProc_ = -1;
    if (prevPid)
        for (int i = 0; i < (int)procs_.size(); ++i)
            if (procs_[i].pid == prevPid) { selProc_ = i; break; }
    // A refreshed process may have loaded new modules or initialized its VM.
    modsForPid_ = 0;
    jdwpInjectPid_ = 0;
}

void CommunicationsTab::renderProcesses(AppContext& ctx) {
    const float scale = theme::UiScale();
    ImGui::SeparatorText("Native Processes");
    if (ui::ToolbarIconButton(DS_ICON_REFRESH, "Refresh", "Re-enumerate running processes") || !enumerated_)
        refreshProcesses();
    ImGui::SameLine();
    ImGui::TextDisabled("%d process(es)", (int)procs_.size());

    DbgSnapshot snap = ctx.debug.snapshot();
    const auto lifecycle = ctx.debug.lifecycleSnapshot();
    if (snap.attached()) {
        ui::SameLineIfFits(160.0f * scale);
        char b[40]; std::snprintf(b, sizeof(b), "debugging PID %u", snap.pid);
        ui::Badge(b, theme::col::good());
    }
    if (lifecycle.busy) {
        ImGui::TextColored(theme::col::warn(), "%s",
            lifecycle.state == DbgLifecycleState::Starting
                ? "Starting debugger..." : "Stopping debugger; restoring owned state...");
        if (lifecycle.command != DbgLifecycleCommand::Detach &&
            lifecycle.state == DbgLifecycleState::Starting) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Cancel startup"))
                ctx.debug.cancelLifecycle(lifecycle.requestId);
        }
    } else if (lifecycle.completed && !lifecycle.error.empty()) {
        ImGui::TextWrapped("%s", lifecycle.error.c_str());
    }
    ui::SearchBox("##pfilter", "process name or PID...", filter_, sizeof(filter_), -1.0f);
    if (!status_.empty()) ImGui::TextWrapped("%s", status_.c_str());

    std::string needle = filter_;
    for (char& c : needle) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    std::vector<int> visible;
    for (int i = 0; i < static_cast<int>(procs_.size()); ++i) {
        std::string haystack = procs_[i].name + " " + std::to_string(procs_[i].pid);
        for (char& c : haystack) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (needle.empty() || haystack.find(needle) != std::string::npos) visible.push_back(i);
    }
    if (visible.empty()) {
        ImGui::TextDisabled(procs_.empty() ? "No processes found. Refresh to try again."
                                          : "No processes match this name or PID.");
        return;
    }

    // Fill the remaining height so the list only scrolls when truly overflowing.
    if (ImGui::BeginTable("procs", 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_Resizable, ImVec2(0, ImGui::GetContentRegionAvail().y))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60 * scale);
        ImGui::TableSetupColumn("Process");
        ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 40 * scale);
        ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 55 * scale);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 110 * scale);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(visible.size()));
        while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const int i = visible[row];
            auto& p = procs_[i];
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(0); ImGui::Text("%u", p.pid);
            ImGui::TableSetColumnIndex(1);
            if (ImGui::Selectable(p.name.c_str(), selProc_ == i,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap))
                selProc_ = i;
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(p.is64 ? "x64" : "x86");
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(p.canOpen ? theme::col::good() : theme::col::bad(),
                               "%s", p.canOpen ? "ok" : "denied");
            ImGui::TableSetColumnIndex(4);
            bool isAttached = snap.attached() && snap.pid == p.pid;
            ImGui::BeginDisabled(lifecycle.busy);
            if (isAttached) {
                if (ImGui::SmallButton("Detach")) {
                    ctx.debug.requestDetach({snap.pid, snap.sessionGeneration});
                    status_.clear();
                }
            } else if (ImGui::SmallButton("Attach")) {
                // App consumes the identity-bound completion even if the user
                // changes workspace while Windows is establishing the session.
                if (ctx.debug.requestAttach(p.pid)) status_.clear();
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            // A live DisasmStudio session owns software/temp/trace/concealment
            // int3 bytes in this process. Passive RPM cannot distinguish those
            // from target code, so refuse a supposedly clean passive dump until
            // the session is detached and every pristine byte is restored.
            ImGui::BeginDisabled(!p.canOpen || isAttached || lifecycle.busy);
            if (ImGui::SmallButton("Dump")) {
                ctx.requestedPassiveDumpPid = p.pid;
                ctx.requestedPassiveDump = true;
            }
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                ImGui::SetTooltip(isAttached
                    ? "Detach first so debugger-owned breakpoint bytes are restored before passive capture."
                    : "Open a read-only snapshot workflow; this does not attach a debugger or inject code.");
            ImGui::PopID();
        }
        }
        ImGui::EndTable();
    }
}

void CommunicationsTab::renderModules() {
    ImGui::SeparatorText("Modules");
    if (selProc_ < 0 || selProc_ >= (int)procs_.size()) {
        ImGui::TextDisabled("Select a process to list its loaded modules.");
        return;
    }
    uint32_t pid = procs_[selProc_].pid;
    if (ImGui::SmallButton("Refresh modules")) modsForPid_ = 0;
    if (pid != modsForPid_) { mods_ = pm_.modules(pid); modsForPid_ = pid; }

    ImGui::TextWrapped("%s (PID %u) - %d module(s)", procs_[selProc_].name.c_str(), pid, (int)mods_.size());
    if (mods_.empty()) {
        ImGui::TextWrapped("No readable module list. The process may have exited or denied access; refresh after it initializes.");
        return;
    }
    if (ImGui::BeginTable("mods", 3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_Resizable, ImVec2(0, ImGui::GetContentRegionAvail().y))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Module");
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 150 * theme::UiScale());
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90 * theme::UiScale());
        ImGui::TableHeadersRow();
        for (auto& m : mods_) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(m.name.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)m.base);
            ImGui::TableSetColumnIndex(2); ImGui::Text("%llu KB", (unsigned long long)(m.size / 1024));
        }
        ImGui::EndTable();
    }
}

void CommunicationsTab::renderConnections(AppContext& ctx) {
    const float scale = theme::UiScale();
    ImGui::SeparatorText("Connections (selected process)");
    pumpConnectionRefresh();
    uint32_t pid = (selProc_ >= 0 && selProc_ < (int)procs_.size()) ? procs_[selProc_].pid : 0;
    if (!pid) {
        if (connsRequestedPid_) requestConnectionRefresh(0);
        // Small hero (no button) bounded to this section's slot, so the panel
        // keeps its place; the process list to the left is the action.
        ImGui::BeginChild("conn_none", ImVec2(0, ImGui::GetContentRegionAvail().y * 0.55f));
        ui::EmptyState(DS_ICON_NETWORK, "No process selected",
                       "Select a process to list its live TCP/UDP connections.");
        ImGui::EndChild();
        return;
    }
    const double now = ImGui::GetTime();
    if (pid != connsRequestedPid_) {
        conns_.clear();
        connStatus_.clear();
        connsForPid_ = 0;
        requestConnectionRefresh(pid);
        connNextRefresh_ = now + 1.0;
    }
    const bool refreshing = connRefreshRunning_.load(std::memory_order_acquire);
    if (connAutoRefresh_) {
        ctx.wantContinuousRedraw = true;
        if (!refreshing && now >= connNextRefresh_) {
            requestConnectionRefresh(pid);
            connNextRefresh_ = now + 1.0;
        }
    }
    if (refreshing) ctx.wantContinuousRedraw = true;

    auto visible = [&](const Conn& c) {
        if (c.ipv6 ? !connShowV6_ : !connShowV4_) return false;
        if (c.protocol == "TCP" ? !connShowTcp_ : !connShowUdp_) return false;
        if (!connFilter_[0]) return true;
        auto contains = [&](const std::string& value) {
            return std::search(value.begin(), value.end(), connFilter_,
                               connFilter_ + std::strlen(connFilter_),
                [](char a, char b) {
                    return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
                }) != value.end();
        };
        return contains(c.local) || contains(c.remote) || contains(c.protocol) ||
               contains(c.family) || contains(c.state);
    };
    size_t shown = 0;
    for (const Conn& c : conns_) if (visible(c)) ++shown;

    ImGui::TextWrapped("%s (PID %u) - %zu/%zu endpoint(s)", procs_[selProc_].name.c_str(),
                pid, shown, conns_.size());
    if (ImGui::SmallButton("Refresh##conn")) {
        requestConnectionRefresh(pid);
        connNextRefresh_ = now + 1.0;
    }
    ui::SameLineIfFits(70.0f * scale); ImGui::Checkbox("Auto##conn", &connAutoRefresh_);
    ui::SameLineIfFits(65.0f * scale); ImGui::Checkbox("IPv4", &connShowV4_);
    ui::SameLineIfFits(65.0f * scale); ImGui::Checkbox("IPv6", &connShowV6_);
    ui::SameLineIfFits(60.0f * scale); ImGui::Checkbox("TCP", &connShowTcp_);
    ui::SameLineIfFits(60.0f * scale); ImGui::Checkbox("UDP", &connShowUdp_);
    ui::SearchBox("##connfilter", "filter endpoint / state...", connFilter_, sizeof(connFilter_),
                  -1.0f);
    if (connRefreshRunning_.load(std::memory_order_acquire)) {
        ImGui::TextDisabled("Refreshing\xE2\x80\xA6");
    }
    if (!connStatus_.empty()) {
        ImGui::PushTextWrapPos();
        ImGui::TextColored(theme::col::warn(), "Partial refresh: %s", connStatus_.c_str());
        ImGui::PopTextWrapPos();
    }
    if (conns_.empty()) {
        if (!refreshing)
            ImGui::TextWrapped("No active IPv4/IPv6 TCP/UDP endpoints were reported for this process.");
        return;
    }
    if (!shown) {
        ImGui::TextWrapped("No endpoints match the current family, protocol, or text filters.");
        return;
    }

    if (ImGui::BeginTable("conns", 5,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                          ImVec2(0, ImGui::GetContentRegionAvail().y))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Local endpoint");
        ImGui::TableSetupColumn("Remote endpoint");
        ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, 52 * scale);
        ImGui::TableSetupColumn("Family", ImGuiTableColumnFlags_WidthFixed, 52 * scale);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 104 * scale);
        ImGui::TableHeadersRow();
        for (const Conn& c : conns_) {
            if (!visible(c)) continue;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(c.local.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(c.remote.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%s", c.protocol.c_str());
            ImGui::TableSetColumnIndex(3); ImGui::TextDisabled("%s", c.family.c_str());
            ImGui::TableSetColumnIndex(4);
            if (c.state == "ESTABLISHED") ImGui::TextColored(theme::col::good(), "%s", c.state.c_str());
            else ImGui::TextDisabled("%s", c.state.c_str());
        }
        ImGui::EndTable();
    }
}

// ---------------------------------------------------------- Java debug (JDWP) --

static const char* jdwpThreadStatusName(int32_t s) {
    switch (s) {
        case JDWP_TS_ZOMBIE:   return "zombie";
        case JDWP_TS_RUNNING:  return "running";
        case JDWP_TS_SLEEPING: return "sleeping";
        case JDWP_TS_MONITOR:  return "monitor wait";
        case JDWP_TS_WAIT:     return "waiting";
    }
    return "?";
}

static std::string jdwpShortClass(const std::string& name) {
    const size_t s = name.find_last_of('/');
    return s == std::string::npos ? name : name.substr(s + 1);
}

// Fetch + disassemble one live method: Method::Bytecodes for the code,
// ReferenceType::ConstantPool (cached per class) for operand symbolication.
// The listing's addresses are the method's bytecode indices (VA == bci).
void CommunicationsTab::loadJdwpMethod(AppContext& ctx, uint64_t classID, uint64_t methodID,
                                       const std::string& label) {
    std::vector<uint8_t> bc;
    if (!ctx.jdwp.bytecodesOf(classID, methodID, bc) || bc.empty()) {
        // Never leave breakpoint actions pointing at a previous method when a
        // newly selected native/abstract method cannot supply bytecode.
        jdwpInsns_.clear();
        jdwpInsnsClass_ = classID;
        jdwpInsnsMethod_ = methodID;
        jdwpInsnsLabel_ = label;
        jdwpStatus_ = "bytecode fetch failed (abstract/native method, or the VM denies canGetBytecodes)";
        return;
    }
    if (jdwpCpClass_ != classID) {
        jdwpCp_.reset();
        uint32_t cnt = 0;
        std::vector<uint8_t> raw;
        if (ctx.jdwp.constantPoolOf(classID, cnt, raw) && cnt) {
            auto cf = std::make_shared<JvmClassFile>();
            if (ParseConstantPoolOnly(raw.data(), raw.size(), (uint16_t)cnt, *cf)) {
                cf->ok = true;                     // cp-only context (no method table)
                jdwpCp_ = std::move(cf);
            }
        }
        jdwpCpClass_ = classID;
    }
    JvmDisassembler dis;
    if (jdwpCp_) dis.attachClass(jdwpCp_);
    jdwpInsns_       = dis.disassemble(bc.data(), bc.size(), 0, 0);
    jdwpInsnsClass_  = classID;
    jdwpInsnsMethod_ = methodID;
    jdwpInsnsLabel_  = label;
    jdwpStatus_.clear();
}

void CommunicationsTab::renderJdwp(AppContext& ctx) {
    const float scale = theme::UiScale();
    JdwpSnapshot snap = ctx.jdwp.snapshot();
    if (!snap.attached()) ctx.jdwpTargetPid = 0;

    const char* st = "detached";
    if (snap.state == JdwpState::Running)   st = "running";
    if (snap.state == JdwpState::Suspended) st = "suspended";
    if (snap.state == JdwpState::Dead)      st = "connection lost";
    char hdr[192];
    std::snprintf(hdr, sizeof(hdr), "Java debug (JDWP) \xE2\x80\x94 %s%s%s###jdwp_hdr",
                  st, snap.vmName.empty() ? "" : ", ", snap.vmName.c_str());
    if (!ImGui::CollapsingHeader(hdr, ImGuiTreeNodeFlags_DefaultOpen))
        return;

    // Housekeeping shared by both attach paths: clear stale per-session UI state.
    auto onAttached = [&] {
        jdwpStatus_.clear();
        jdwpSelClass_ = jdwpInsnsClass_ = jdwpInsnsMethod_ = jdwpCpClass_ = 0;
        jdwpMethods_.clear();
        jdwpInsns_.clear();
        jdwpCp_.reset();
        jdwpSelClassName_.clear();
        jdwpInsnsLabel_.clear();
        jdwpClassesRef_.reset();
        jdwpFiltered_.clear();
        jdwpScrollToStop_ = false;
        jdwpSeenStopClass_ = jdwpSeenStopMethod_ = 0;
        jdwpSeenStopBci_ = ~0ull;
    };

    if (!snap.attached()) {
        jdwpPort_ = jdwpPort_ < 1 ? 1 : jdwpPort_ > 65535 ? 65535 : jdwpPort_;

        // --- Primary path: inject the JDWP agent into a RUNNING JVM (no -agentlib
        //     prelaunch flag). Selection is local to the Java workspace. ---
        ImGui::SeparatorText("Attach to a running Java process");
        if (!enumerated_) refreshProcesses();
        if (ui::ToolbarIconButton(DS_ICON_REFRESH, "Refresh processes", "Refresh running processes and re-check the selected JVM"))
            refreshProcesses();
        const std::string processPreview = selProc_ >= 0 && selProc_ < static_cast<int>(procs_.size())
            ? procs_[selProc_].name + " (PID " + std::to_string(procs_[selProc_].pid) + ")"
            : "Select a Java process...";
        ImGui::SetNextItemWidth((std::min)(500.0f * scale, ImGui::GetContentRegionAvail().x));
        if (ImGui::BeginCombo("##jdwp_process", processPreview.c_str())) {
            ui::SearchBox("##jdwp_process_filter", "process name or PID...",
                          jdwpProcessFilter_, sizeof(jdwpProcessFilter_), -1.0f);
            std::string needle = jdwpProcessFilter_;
            for (char& c : needle) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            size_t shown = 0;
            for (int i = 0; i < static_cast<int>(procs_.size()); ++i) {
                const std::string label = procs_[i].name + " (PID " + std::to_string(procs_[i].pid) + ")";
                std::string haystack = label;
                for (char& c : haystack) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (!needle.empty() && haystack.find(needle) == std::string::npos) continue;
                ++shown;
                ImGui::PushID(i);
                if (ImGui::Selectable(label.c_str(), selProc_ == i)) selProc_ = i;
                ImGui::PopID();
            }
            if (!shown) ImGui::TextDisabled("No processes match this name or PID.");
            ImGui::EndCombo();
        }
        uint32_t selPid = (selProc_ >= 0 && selProc_ < (int)procs_.size()) ? procs_[selProc_].pid : 0;
        const std::string selName = selPid ? procs_[selProc_].name : std::string();
        if (selPid != jdwpInjectPid_) {           // re-inspect the VM on selection change
            jdwpInjectPid_  = selPid;
            jdwpInjectInfo_ = selPid ? InspectJvm(selPid) : JvmInfo{};
            jdwpInjectNextPoll_ = ImGui::GetTime() + 1.0;
        } else if (selPid && !jdwpInjectInfo_.hosts() && ImGui::GetTime() >= jdwpInjectNextPoll_) {
            // A native EXE launcher loads jvm.dll only after it starts, so a process
            // selected early shows "(no JVM detected)". Keep re-checking (throttled)
            // until the VM appears, so the badge flips to HotSpot without a reselect.
            jdwpInjectInfo_ = InspectJvm(selPid);
            jdwpInjectNextPoll_ = ImGui::GetTime() + 1.0;
        }
        const JvmInfo& ji = jdwpInjectInfo_;
        if (!selPid) {
            ImGui::TextWrapped("Choose a process above to detect its JVM and enable attachment. No JVM debug flags are needed for supported HotSpot x64 targets.");
        } else {
            ImGui::Text("Selected: %s (PID %u)", selName.c_str(), selPid);
            ui::SameLineIfFits(125.0f * scale);
            if (ji.flavor == JvmFlavor::HotSpot)
                ui::Badge(ji.is64 ? "HotSpot x64" : "HotSpot x86", theme::col::good());
            else if (ji.flavor == JvmFlavor::OpenJ9)
                ui::Badge("OpenJ9", theme::col::warn());
            else
                ImGui::TextDisabled("(no JVM detected)");

            // Injection works only for a 64-bit HotSpot VM.
            const bool canInject = ji.flavor == JvmFlavor::HotSpot && ji.is64;
            ImGui::BeginDisabled(!canInject);
            if (ImGui::Button("Attach (inject JDWP)##jdwpinject")) {
                JvmAttachResult ar = LoadJdwpAgent(selPid, (uint16_t)jdwpPort_);
                // A refused or unconfirmed load does not prove that a listener
                // on this port belongs to the selected PID. Only a confirmed
                // load permits automatic connection and PID attribution. One
                // bounded connection attempt also avoids stacking eight 15s RPC
                // waits on the render thread.
                std::string err;
                const bool connected = ar.ok && ctx.jdwp.attach(
                    "127.0.0.1", (uint16_t)jdwpPort_, err);
                if (connected) {
                    onAttached();
                    ctx.jdwpTargetPid = selPid;   // scope the Connections "attached only" view
                    // Freeze the VM immediately so the launcher's Java main logic can be
                    // breakpointed before it runs on. The agent stays suspend=n (no frozen
                    // orphan if the connect had failed); one Resume releases this cleanly.
                    if (jdwpSuspendOnAttach_) ctx.jdwp.suspendAll();
                    const bool nowSuspended = ctx.jdwp.snapshot().state == JdwpState::Suspended;
                    ui::Toast(ui::ToastKind::Success,
                              std::string("Attached to JVM PID ") + std::to_string(selPid) +
                              (nowSuspended ? " (suspended)" : " (running)"));
                } else {
                    ctx.jdwpTargetPid = 0;
                    jdwpStatus_ = ar.ok
                        ? "The agent loaded, but the connection failed: " + err
                        : ar.enqueued
                            ? "The VM accepted the agent load request, but did not confirm that the agent started."
                            : "The agent was not loaded: " + ar.error;
                    jdwpStatus_ += "\nVerify the agent's host and port, then use Connect below to try a listening agent.";
                    if (!ar.agentOutput.empty()) jdwpStatus_ += "\nVM said: " + ar.agentOutput;
                    ui::Toast(ar.enqueued && !ar.ok ? ui::ToastKind::Warn : ui::ToastKind::Error,
                              "JVM attachment is incomplete; details appear in the Java debug panel.");
                }
            }
            ImGui::EndDisabled();
            ui::SameLineIfFits(120.0f * scale);
            ImGui::SetNextItemWidth(80.0f * scale);
            ImGui::InputInt("port##jdwpinj", &jdwpPort_, 0, 0);
            jdwpPort_ = (std::clamp)(jdwpPort_, 1, 65535);
            ui::SameLineIfFits(170.0f * scale);
            ImGui::Checkbox("Suspend on attach##jdwpsusp", &jdwpSuspendOnAttach_);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Freeze every Java thread the instant we connect, so you can set\n"
                                  "breakpoints in the launcher's main logic before it runs on.\n"
                                  "Click Resume to let it continue. Recommended for EXE launchers\n"
                                  "that hand off to an embedded JVM.");
            if (ji.flavor == JvmFlavor::OpenJ9)
                ImGui::TextColored(theme::col::warn(), "OpenJ9 uses a different attach protocol \xE2\x80\x94 launch with -agentlib:jdwp and use the host:port connect below.");
            else if (ji.flavor == JvmFlavor::HotSpot && !ji.is64)
                ImGui::TextWrapped("32-bit JVM: launch it with -agentlib:jdwp and connect below for bytecode debugging, or use Processes & Attach for native debugging.");
            else if (ji.flavor == JvmFlavor::None)
                ImGui::TextDisabled("This process has no jvm.dll loaded. Pick a java/javaw process (or one embedding a JVM).");
            else
                ImGui::TextDisabled("Loads the JDWP agent into the live VM, then connects \xE2\x80\x94 no restart, no launch flags.");
        }

        // --- Secondary path: connect to an agent that is ALREADY listening
        //     (remote target, or a VM launched with -agentlib:jdwp). ---
        ImGui::SeparatorText("Or connect to a listening JDWP agent");
        ImGui::SetNextItemWidth(150.0f * scale);
        ImGui::InputTextWithHint("##jdwphost", "host", jdwpHost_, sizeof(jdwpHost_));
        ui::SameLineIfFits(135.0f * scale);
        ImGui::SetNextItemWidth(90.0f * scale);
        ImGui::InputInt("Port##jdwpport", &jdwpPort_, 0, 0);
        jdwpPort_ = jdwpPort_ < 1 ? 1 : jdwpPort_ > 65535 ? 65535 : jdwpPort_;
        ui::SameLineIfFits(90.0f * scale);
        if (ImGui::Button("Connect##jdwp")) {
            std::string err;
            if (ctx.jdwp.attach(jdwpHost_, (uint16_t)jdwpPort_, err)) {
                onAttached();
                if (jdwpSuspendOnAttach_) ctx.jdwp.suspendAll();
            } else jdwpStatus_ = err;
        }
        ImGui::TextWrapped("Host and port of a VM started with -agentlib:jdwp=...,server=y,address=*:%d", jdwpPort_);
        if (!jdwpStatus_.empty()) {
            ImGui::PushTextWrapPos();
            ImGui::TextColored(theme::col::bad(), "%s", jdwpStatus_.c_str());
            ImGui::PopTextWrapPos();
        }
        if (snap.state == JdwpState::Dead)
            ImGui::TextWrapped("Last session: %s", snap.lastEvent.c_str());
        return;
    }

    // ---- control strip ------------------------------------------------------
    const bool suspended = snap.state == JdwpState::Suspended;
    if (suspended) {
        if (ImGui::Button("Resume##jdwp")) ctx.jdwp.resumeAll();
        ui::SameLineIfFits(100.0f * scale);
        ImGui::BeginDisabled(!snap.stopThread || !snap.stopLoc.classID);
        if (ImGui::Button("Step Into##jdwp")) ctx.jdwp.stepInto();
        ui::SameLineIfFits(105.0f * scale);
        if (ImGui::Button("Step Over##jdwp")) ctx.jdwp.stepOver();
        ui::SameLineIfFits(100.0f * scale);
        if (ImGui::Button("Step Out##jdwp")) ctx.jdwp.stepOut();
        ImGui::EndDisabled();
    } else {
        if (ImGui::Button("Suspend##jdwp")) ctx.jdwp.suspendAll();
    }
    ui::SameLineIfFits(150.0f * scale);
    if (ImGui::Button("Refresh classes##jdwp")) ctx.jdwp.refreshClasses();
    ui::SameLineIfFits(80.0f * scale);
    if (ImGui::Button("Detach##jdwp")) {
        ctx.jdwp.detach();
        ctx.jdwpTargetPid = 0;
        return;
    }
    ImGui::PushTextWrapPos();
    ImGui::TextDisabled("%s%s%s \xC2\xB7 %s", snap.vmName.c_str(),
                        snap.vmVersion.empty() ? "" : " ",
                        snap.vmVersion.c_str(), snap.lastEvent.c_str());
    if (!jdwpStatus_.empty()) ImGui::TextColored(theme::col::bad(), "%s", jdwpStatus_.c_str());
    ImGui::PopTextWrapPos();

    // ---- auto-follow a fresh stop (breakpoint hit / step landed) -------------
    if (suspended && snap.stopLoc.classID &&
        (snap.stopLoc.classID != jdwpSeenStopClass_ ||
         snap.stopLoc.methodID != jdwpSeenStopMethod_ ||
         snap.stopLoc.index != jdwpSeenStopBci_)) {
        jdwpSeenStopClass_  = snap.stopLoc.classID;
        jdwpSeenStopMethod_ = snap.stopLoc.methodID;
        jdwpSeenStopBci_    = snap.stopLoc.index;
        if (snap.stopLoc.classID != jdwpInsnsClass_ ||
            snap.stopLoc.methodID != jdwpInsnsMethod_) {
            std::string lbl = snap.frames.empty() ? "(stopped method)" : snap.frames.front().label;
            loadJdwpMethod(ctx, snap.stopLoc.classID, snap.stopLoc.methodID, lbl);
        }
        jdwpScrollToStop_ = true;
    }

    // ---- three-column console -------------------------------------------------
    ImGui::SetNextWindowContentSize(ImVec2(
        (std::max)(ImGui::GetContentRegionAvail().x - ImGui::GetStyle().WindowPadding.x * 2.0f,
                    940.0f * scale), 0.0f));
    ImGui::BeginChild("jdwp_body", ImVec2(0, (std::max)(380.0f * scale,
        ImGui::GetContentRegionAvail().y)), ImGuiChildFlags_Borders,
        ImGuiWindowFlags_HorizontalScrollbar);
    const float colW = ImGui::GetContentRegionAvail().x;

    // -- column 1: threads / breakpoints / session log --
    ImGui::BeginChild("jdwp_left", ImVec2(colW * 0.28f, 0));
    ImGui::SeparatorText("Threads");
    ImGui::BeginChild("jdwp_threads", ImVec2(0, 110.0f * scale));
    for (const auto& t : snap.threads) {
        const bool isStop = suspended && t.id == snap.stopThread;
        if (isStop) ImGui::TextColored(theme::col::good(), "> %s", t.name.c_str());
        else        ImGui::Text("  %s", t.name.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("(%s)", jdwpThreadStatusName(t.status));
    }
    if (snap.threads.empty()) ImGui::TextDisabled("(suspend to list threads)");
    ImGui::EndChild();

    ImGui::SeparatorText("Breakpoints");
    ImGui::BeginChild("jdwp_bps", ImVec2(0, 90.0f * scale));
    int removeBp = INT32_MIN;
    for (const auto& b : snap.breakpoints) {
        ImGui::PushID(b.requestID);
        if (ImGui::SmallButton("x")) removeBp = b.requestID;
        ImGui::SameLine();
        ImGui::Text("%s", b.label.c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("hits %u", b.hits);
        ImGui::PopID();
    }
    if (snap.breakpoints.empty()) ImGui::TextDisabled("(right-click a bytecode row)");
    ImGui::EndChild();
    if (removeBp != INT32_MIN) ctx.jdwp.clearBreakpoint(removeBp);

    ImGui::SeparatorText("Events");
    ImGui::BeginChild("jdwp_log", ImVec2(0, 0));
    const size_t logStart = snap.events.size() > 50 ? snap.events.size() - 50 : 0;
    for (size_t i = logStart; i < snap.events.size(); ++i)
        ImGui::TextDisabled("%s", snap.events[i].c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4.0f) ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
    ImGui::EndChild();   // jdwp_left
    ImGui::SameLine();

    // -- column 2: class browser + methods --
    ImGui::BeginChild("jdwp_mid", ImVec2(colW * 0.30f, 0));
    ImGui::SeparatorText("Classes");
    ui::SearchBox("##jdwpclsfilter", "filter classes...", jdwpClassFilter_, sizeof(jdwpClassFilter_), -1.0f);
    // Rebuild the filtered index when the class list or the filter changes.
    if (snap.classes != jdwpClassesRef_ || jdwpFilterCache_ != jdwpClassFilter_) {
        jdwpClassesRef_ = snap.classes;
        jdwpFilterCache_ = jdwpClassFilter_;
        jdwpFiltered_.clear();
        if (jdwpClassesRef_) {
            std::string needle = jdwpFilterCache_;
            for (char& ch : needle) ch = (char)std::tolower((unsigned char)ch);
            for (int i = 0; i < (int)jdwpClassesRef_->size(); ++i) {
                if (!needle.empty()) {
                    std::string hay = (*jdwpClassesRef_)[i].name;
                    for (char& ch : hay) ch = (char)std::tolower((unsigned char)ch);
                    if (hay.find(needle) == std::string::npos) continue;
                }
                jdwpFiltered_.push_back(i);
                if (jdwpFiltered_.size() >= 2000) break;   // plenty for a filtered browse
            }
        }
    }
    ImGui::TextDisabled("%zu class(es)%s", jdwpFiltered_.size(),
                        jdwpFiltered_.size() >= 2000 ? " (capped, narrow the filter)" : "");
    ImGui::BeginChild("jdwp_classes", ImVec2(0, 160.0f * scale), ImGuiChildFlags_Borders);
    {
        ImGuiListClipper clip;
        clip.Begin((int)jdwpFiltered_.size());
        while (clip.Step()) {
            for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
                const JdwpClassRow& c = (*jdwpClassesRef_)[jdwpFiltered_[row]];
                ImGui::PushID(row);
                if (ImGui::Selectable(c.name.c_str(), c.typeID == jdwpSelClass_)) {
                    jdwpSelClass_     = c.typeID;
                    jdwpSelClassName_ = c.name;
                    jdwpMethods_.clear();
                    if (!ctx.jdwp.methodsOf(c.typeID, jdwpMethods_))
                        jdwpStatus_ = "method list fetch failed";
                }
                ImGui::PopID();
            }
        }
    }
    ImGui::EndChild();

    ImGui::SeparatorText("Methods");
    ImGui::BeginChild("jdwp_methods", ImVec2(0, 0), ImGuiChildFlags_Borders);
    for (size_t i = 0; i < jdwpMethods_.size(); ++i) {
        const auto& m = jdwpMethods_[i];
        ImGui::PushID((int)i);
        const bool cur = jdwpSelClass_ == jdwpInsnsClass_ && m.methodID == jdwpInsnsMethod_;
        char row[320];
        std::snprintf(row, sizeof(row), "%s%s", m.name.c_str(), m.signature.c_str());
        if (ImGui::Selectable(row, cur))
            loadJdwpMethod(ctx, jdwpSelClass_, m.methodID,
                           jdwpShortClass(jdwpSelClassName_) + "." + m.name);
        ImGui::PopID();
    }
    if (jdwpMethods_.empty()) ImGui::TextDisabled("(select a class)");
    ImGui::EndChild();
    ImGui::EndChild();   // jdwp_mid
    ImGui::SameLine();

    // -- column 3: call stack + live bytecode listing --
    ImGui::BeginChild("jdwp_right", ImVec2(0, 0));
    if (suspended && !snap.frames.empty()) {
        ImGui::SeparatorText("Call stack");
        ImGui::BeginChild("jdwp_frames", ImVec2(0, 84.0f * scale));
        for (size_t i = 0; i < snap.frames.size(); ++i) {
            const auto& f = snap.frames[i];
            ImGui::PushID((int)i);
            char row[300];
            std::snprintf(row, sizeof(row), "#%zu  %s", i, f.label.c_str());
            const bool cur = f.loc.classID == jdwpInsnsClass_ && f.loc.methodID == jdwpInsnsMethod_ && i == 0;
            if (ImGui::Selectable(row, cur))
                loadJdwpMethod(ctx, f.loc.classID, f.loc.methodID, f.label);
            ImGui::PopID();
        }
        ImGui::EndChild();
    }

    ImGui::SeparatorText(jdwpInsns_.empty() ? "Bytecode" : ("Bytecode \xE2\x80\x94 " + jdwpInsnsLabel_).c_str());
    ImGui::BeginChild("jdwp_code", ImVec2(0, 0), ImGuiChildFlags_Borders);
    if (jdwpInsns_.empty()) {
        ImGui::TextDisabled("Select a class, then a method \xE2\x80\x94 or hit a breakpoint \xE2\x80\x94 to see its live bytecode.");
        ImGui::TextDisabled("Right-click a row to set a JDWP breakpoint at that bci.");
    } else {
        const bool stopHere = suspended &&
            snap.stopLoc.classID == jdwpInsnsClass_ && snap.stopLoc.methodID == jdwpInsnsMethod_;
        // The stop row must be submitted for SetScrollHereY to reach it, even
        // when the clipper would skip it (same pattern as the static listing).
        int stopRow = -1;
        if (stopHere && jdwpScrollToStop_)
            for (int i = 0; i < (int)jdwpInsns_.size(); ++i)
                if (jdwpInsns_[i].address == snap.stopLoc.index) { stopRow = i; break; }
        ImGuiListClipper clip;
        clip.Begin((int)jdwpInsns_.size());
        if (stopRow >= 0) clip.IncludeItemByIndex(stopRow);
        while (clip.Step()) {
            for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
                const Instruction& in = jdwpInsns_[row];
                ImGui::PushID(row);
                const bool isStopRow = stopHere && in.address == snap.stopLoc.index;
                bool hasBp = false;
                for (const auto& b : snap.breakpoints)
                    if (b.loc.classID == jdwpInsnsClass_ && b.loc.methodID == jdwpInsnsMethod_ &&
                        b.loc.index == in.address) { hasBp = true; break; }

                const std::string instruction = InstructionText(in);
                char line[512];
                std::snprintf(line, sizeof(line), "%c%5llu:  %-39s%s%s",
                              isStopRow ? '>' : hasBp ? '*' : ' ',
                              (unsigned long long)in.address,
                              instruction.c_str(),
                              in.comment.empty() ? "" : "  ; ",
                              in.comment.c_str());
                if (isStopRow)    ImGui::PushStyleColor(ImGuiCol_Text, theme::col::good());
                else if (hasBp)   ImGui::PushStyleColor(ImGuiCol_Text, theme::col::bad());
                ImGui::Selectable(line, isStopRow);
                if (isStopRow || hasBp) ImGui::PopStyleColor();
                if (isStopRow && jdwpScrollToStop_) {
                    ImGui::SetScrollHereY(0.4f);
                    jdwpScrollToStop_ = false;
                }
                if (ImGui::BeginPopupContextItem("jdwp_row_ctx")) {
                    if (!hasBp && ImGui::MenuItem("Set breakpoint here")) {
                        JdwpLocation loc{1, jdwpInsnsClass_, jdwpInsnsMethod_, in.address};
                        char lbl[256];
                        std::snprintf(lbl, sizeof(lbl), "%s bci=%llu", jdwpInsnsLabel_.c_str(),
                                      (unsigned long long)in.address);
                        std::string err;
                        if (!ctx.jdwp.setBreakpoint(loc, lbl, err)) jdwpStatus_ = err;
                    }
                    if (hasBp && ImGui::MenuItem("Remove breakpoint")) {
                        for (const auto& b : snap.breakpoints)
                            if (b.loc.classID == jdwpInsnsClass_ &&
                                b.loc.methodID == jdwpInsnsMethod_ &&
                                b.loc.index == in.address) {
                                ctx.jdwp.clearBreakpoint(b.requestID);
                                break;
                            }
                    }
                    ImGui::EndPopup();
                }
                ImGui::PopID();
            }
        }
    }
    ImGui::EndChild();   // jdwp_code
    ImGui::EndChild();   // jdwp_right

    ImGui::EndChild();   // jdwp_body
}

void CommunicationsTab::renderGameMaker(AppContext& ctx) {
    const float scale = theme::UiScale();
    const auto archive=ctx.staticBinary().gameMakerArchive();
    const auto session=ctx.debug.gameMakerSnapshot();
    const auto fallback=ctx.frameDebugSnapshot?DbgSnapshot{}:ctx.debug.snapshot();
    const auto& native=ctx.frameDebugSnapshot?*ctx.frameDebugSnapshot:fallback;
    const bool matching=native.attached() && DebugTargetIdentityMatches(session.target,{native.pid,native.sessionGeneration});
    const bool paused=matching && native.state==DbgState::Paused && session.state==GameMakerSessionState::Paused && session.stop && session.stop->identity.tid==native.activeTid;
    ImGui::TextUnformatted("GameMaker / GML instruction debugger");
    ImGui::TextWrapped("Open the game's data.win as a document, attach its running process in Processes & Attach, then start GML debugging here.");
    ImGui::Text("Native target: %s",native.attached()?std::to_string(native.pid).c_str():"not attached");
    if(archive)ImGui::Text("Archive: %s (%zu code entries)",archive->gameName.c_str(),archive->code.size());
    else ImGui::TextDisabled("The active document is not a GameMaker archive.");
    const bool canStart=native.attached() && archive && archive->ok && archive->bytecodeSupported &&
        session.state==GameMakerSessionState::Disconnected;
    ImGui::BeginDisabled(!canStart);
    if(ImGui::Button("Start GML debugging")){
        gmlStatus_.clear();
        if(ctx.debug.connectGameMaker(archive,ctx.staticBinary().path(),ctx.staticBinary().contentHash(),ctx.staticProject().gmlBreakpoints,gmlStatus_))ctx.gmlExecutionMode=true;
    }
    ImGui::EndDisabled();ui::SameLineIfFits(170.0f * scale);
    ImGui::BeginDisabled(session.state==GameMakerSessionState::Disconnected || session.state==GameMakerSessionState::Inert);
    if(ImGui::Button("Stop GML debugging"))ctx.debug.disconnectGameMaker();
    ImGui::EndDisabled();
    ImGui::TextWrapped("The built-in helper verifies the runner and archive, then observes GML instruction boundaries. Game files are unchanged.");
    ImGui::Separator();
    if(!session.runnerName.empty())ImGui::Text("Runner: %s",session.runnerName.c_str());
    if(!session.status.empty())ImGui::TextWrapped("%s",session.status.c_str());
    ImGui::Text("Breakpoints: %u requested / %u bound",session.requestedBreakpoints,session.boundBreakpoints);
    if(session.capabilities.runtimeVerified){
        ImGui::TextDisabled("Verified adapter: instruction stops, call-aware steps, frames and numeric storage");
        ImGui::TextDisabled("Packed operand-stack values and complex-value edits are unavailable in this adapter.");
    }
    ImGui::Text("Instruction stops: %s",session.instructionStopsVerified?"verified":"not yet verified");
    if(session.mappingRetained){
        if(session.ready() || session.state==GameMakerSessionState::Initializing || session.state==GameMakerSessionState::Installing)
            ImGui::TextDisabled("The verified helper is loaded for this connection.");
        else if(session.state==GameMakerSessionState::Inert)ImGui::TextDisabled("The disabled helper mapping remains until the target exits.");
        else if(session.state==GameMakerSessionState::Disabling)ImGui::TextDisabled("Waiting for callback draining and helper unload.");
        else ImGui::TextDisabled("The helper mapping is retained; review the connection error before continuing.");
    }
    if(!session.error.empty())ImGui::TextColored(theme::col::warn(),"%s",session.error.c_str());
    if(!gmlStatus_.empty())ImGui::TextColored(theme::col::warn(),"%s",gmlStatus_.c_str());
    auto command=[&](GmlControlCommand c){gmlStatus_.clear();ctx.debug.gameMakerCommand(c,paused?session.stop->identity:GmlPauseIdentity{},gmlStatus_);};
    ImGui::SeparatorText("Execution");
    ImGui::BeginDisabled(!matching || !session.ready() || (!paused && native.state!=DbgState::Running));
    if(ImGui::Button(paused?"Continue GML":"Pause GML"))command(paused?GmlControlCommand::Continue:GmlControlCommand::Pause);
    ImGui::EndDisabled();ui::SameLineIfFits(125.0f * scale);
    ImGui::BeginDisabled(!paused);
    if(ImGui::Button("Step Into GML"))command(GmlControlCommand::StepInto);ui::SameLineIfFits(130.0f * scale);
    if(ImGui::Button("Step Over GML"))command(GmlControlCommand::StepOver);ui::SameLineIfFits(125.0f * scale);
    if(ImGui::Button("Step Out GML"))command(GmlControlCommand::StepOut);
    ImGui::EndDisabled();
    if(native.state==DbgState::Paused && matching && !paused)ImGui::TextDisabled("This is a native pause. GML frame and numeric-edit authority are unavailable.");
    ImGui::Checkbox("Use GML execution controls in the toolbar",&ctx.gmlExecutionMode);
    ImGui::Checkbox("Follow GML stops in Binary View",&ctx.gmlAutoFollow);
    if(paused && session.archive && session.stop->location.codeIndex<session.archive->code.size()){
        const auto& code=session.archive->code[session.stop->location.codeIndex];
        ImGui::Text("Stopped in %s + %u",code.name.c_str(),session.stop->location.byteOffset);
        const bool sameArchive=archive && ctx.staticBinary().contentHash()==session.archiveHash;
        ImGui::BeginDisabled(!sameArchive);
        if(ImGui::Button("Show GML instruction"))ctx.gotoAddress(code.bytecodeOffset+session.stop->location.byteOffset);
        ImGui::EndDisabled();
        if(!sameArchive)ImGui::TextDisabled("Activate the connected archive document to navigate this stop.");
    }
}

void CommunicationsTab::render(AppContext& ctx) {
    const float scale = theme::UiScale();
    ImGui::TextUnformatted("Communications");
    ui::SameLineIfFits(330.0f * scale);
    ImGui::TextDisabled("Processes, connections and runtime debugging");
    static const char* views[] = {
        "Processes & Attach", "Network Monitor", "Java / JDWP", "GameMaker / GML"
    };

    if (ctx.requestedLiveObservation) {
        ctx.requestedLiveObservation = false;
        workspaceView_ = 1;
        systemConnections_.requestLiveObservation(
            ctx.requestedLiveObservationDocument,
            ctx.requestedLiveObservationImageGeneration);
    }

    // A real workspace switcher, rather than three large tools stacked into one
    // scrolling page.  Each mode receives the full content viewport and keeps its
    // retained state while the user moves between them.
    if(ctx.requestedGameMakerConnection){ctx.requestedGameMakerConnection=false;workspaceView_=3;}
    workspaceView_ = ui::TabStrip("##communications_views", views, 4,
                                   workspaceView_);

    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,
                        ImVec2(7.0f * scale, 6.0f * scale));

    if (workspaceView_ == 1) {
        ImGui::BeginChild("##communications_network", ImVec2(0, 0),
                          ImGuiChildFlags_None);
        systemConnections_.render(ctx);
        ImGui::EndChild();
    } else if(workspaceView_==3){
        ImGui::BeginChild("##communications_gamemaker",ImVec2(0,0),ImGuiChildFlags_None);
        renderGameMaker(ctx);ImGui::EndChild();
    } else if (workspaceView_ == 2) {
        ImGui::BeginChild("##communications_java", ImVec2(0, 0),
                          ImGuiChildFlags_None);
        renderJdwp(ctx);
        ImGui::EndChild();
    } else {
        const ImVec2 avail = ImGui::GetContentRegionAvail();
        const float divider = 5.0f * scale;
        const bool stacked = avail.x < 800.0f * scale;
        if (processPaneWidth_ <= 0.0f) processPaneWidth_ = avail.x * 0.46f;
        if (!stacked)
            processPaneWidth_ = std::clamp(processPaneWidth_, 380.0f * scale,
                                            avail.x - 340.0f * scale - divider);
        const float processHeight = stacked
            ? (std::max)(1.0f, (std::min)(280.0f * scale, avail.y * 0.46f)) : 0.0f;

        ImGui::BeginChild("c_proc", ImVec2(stacked ? 0.0f : processPaneWidth_, processHeight),
                          ImGuiChildFlags_Borders);
        renderProcesses(ctx);
        ImGui::EndChild();
        if (!stacked)
            ui::VSplitter("##communications_split", &processPaneWidth_,
                          380.0f * scale, 340.0f * scale, divider);
        ImGui::BeginChild("c_right", ImVec2(0, 0),
                          ImGuiChildFlags_Borders);
        if (ImGui::BeginTabBar("##process_details")) {
            if (ImGui::BeginTabItem("Modules")) {
                renderModules();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Connections")) {
                renderConnections(ctx);
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::EndChild();
    }

    ImGui::PopStyleVar(3);
}

} // namespace ds
