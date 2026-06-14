#include "ConnectionsTab.h"
// Winsock before windows.h; iphlpapi for the owner-PID tables + TCP ESTATS.
#include <winsock2.h>
#include <windows.h>
#include <commdlg.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tcpestats.h>   // TCP_ESTATS_DATA_RW_v0 / _ROD_v0 for per-connection byte counts
#include "../Ui/Fonts.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "iphlpapi.lib")

namespace ds {

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

static void fmt4(unsigned long addr, unsigned long port, char* out, size_t n) {
    struct in_addr a; a.S_un.S_addr = (ULONG)addr;
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a, ip, sizeof(ip));
    std::snprintf(out, n, "%s:%u", ip, (unsigned)ntohs((u_short)port));
}
static void fmt6(const UCHAR addr[16], unsigned long port, char* out, size_t n) {
    char ip[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, (void*)addr, ip, sizeof(ip));
    std::snprintf(out, n, "[%s]:%u", ip, (unsigned)ntohs((u_short)port));
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
    const uint32_t dtMs = lastPollTick_ ? (now - lastPollTick_) : 0;
    lastPollTick_ = now;

    if (pidNames_.empty() || (uint32_t)(now - namesPollTick_) > 3000) {
        namesPollTick_ = now;
        pidNames_.clear();
        for (const auto& p : pm_.enumerate()) pidNames_[p.pid] = p.name;
    }

    std::unordered_map<std::string, size_t> idx;
    idx.reserve(log_.size() * 2);
    for (size_t i = 0; i < log_.size(); ++i) {
        log_[i].active = false;
        log_[i].rateIn = log_[i].rateOut = 0.0;
        idx[log_[i].proto + '|' + log_[i].local + '|' + log_[i].remote + '|' +
            std::to_string(log_[i].pid)] = i;
    }

    auto touch = [&](const char* proto, const std::string& local, const std::string& remote,
                     const std::string& state, uint32_t pid,
                     bool haveBytes, uint64_t inB, uint64_t outB) -> ConnRecord& {
        std::string key = std::string(proto) + '|' + local + '|' + remote + '|' + std::to_string(pid);
        auto it = idx.find(key);
        ConnRecord* r;
        if (it != idx.end()) { r = &log_[it->second]; }
        else {
            ConnRecord nr;
            nr.proto = proto; nr.local = local; nr.remote = remote;
            nr.pid = pid; nr.firstSeen = now;
            auto pn = pidNames_.find(pid);
            nr.proc = (pn != pidNames_.end()) ? pn->second : "";
            idx[key] = log_.size();
            log_.push_back(std::move(nr));
            r = &log_.back();
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
    DWORD sz = 0;
    bool estatsOk = false;

    // IPv4 TCP (+ ESTATS bytes on established connections)
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    for (int a = 0; sz && a < 3; ++a) {
        buf.assign(sz, 0);
        DWORD rc = GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& e = t->table[i];
                char ls[64], rs[64];
                fmt4(e.dwLocalAddr, e.dwLocalPort, ls, sizeof(ls));
                fmt4(e.dwRemoteAddr, e.dwRemotePort, rs, sizeof(rs));
                uint64_t inB = 0, outB = 0; bool hb = false;
                if (e.dwState == MIB_TCP_STATE_ESTAB) {
                    MIB_TCPROW row{};
                    row.dwState = e.dwState; row.dwLocalAddr = e.dwLocalAddr;
                    row.dwLocalPort = e.dwLocalPort; row.dwRemoteAddr = e.dwRemoteAddr;
                    row.dwRemotePort = e.dwRemotePort;
                    hb = readEstats(row, false, inB, outB);
                    estatsOk = estatsOk || hb;
                }
                touch("TCP", ls, rs, tcpState(e.dwState), e.dwOwningPid, hb, inB, outB);
            }
            break;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER) break;
    }
    // IPv6 TCP
    sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    for (int a = 0; sz && a < 3; ++a) {
        buf.assign(sz, 0);
        DWORD rc = GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& e = t->table[i];
                char ls[80], rs[80];
                fmt6(e.ucLocalAddr, e.dwLocalPort, ls, sizeof(ls));
                fmt6(e.ucRemoteAddr, e.dwRemotePort, rs, sizeof(rs));
                uint64_t inB = 0, outB = 0; bool hb = false;
                if (e.dwState == MIB_TCP_STATE_ESTAB) {
                    MIB_TCP6ROW row{};
                    std::memcpy(&row.LocalAddr, e.ucLocalAddr, 16);
                    row.dwLocalScopeId = e.dwLocalScopeId; row.dwLocalPort = e.dwLocalPort;
                    std::memcpy(&row.RemoteAddr, e.ucRemoteAddr, 16);
                    row.dwRemoteScopeId = e.dwRemoteScopeId; row.dwRemotePort = e.dwRemotePort;
                    row.State = (MIB_TCP_STATE)e.dwState;
                    hb = readEstats(row, true, inB, outB);
                    estatsOk = estatsOk || hb;
                }
                touch("TCP6", ls, rs, tcpState(e.dwState), e.dwOwningPid, hb, inB, outB);
            }
            break;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER) break;
    }
    // IPv4 UDP
    sz = 0;
    GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    for (int a = 0; sz && a < 3; ++a) {
        buf.assign(sz, 0);
        DWORD rc = GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (rc == NO_ERROR) {
            auto* u = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < u->dwNumEntries; ++i) {
                const auto& e = u->table[i];
                char ls[64];
                fmt4(e.dwLocalAddr, e.dwLocalPort, ls, sizeof(ls));
                touch("UDP", ls, "*", "listen", e.dwOwningPid, false, 0, 0);
            }
            break;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER) break;
    }
    // IPv6 UDP
    sz = 0;
    GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    for (int a = 0; sz && a < 3; ++a) {
        buf.assign(sz, 0);
        DWORD rc = GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
        if (rc == NO_ERROR) {
            auto* u = reinterpret_cast<MIB_UDP6TABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < u->dwNumEntries; ++i) {
                const auto& e = u->table[i];
                char ls[80];
                fmt6(e.ucLocalAddr, e.dwLocalPort, ls, sizeof(ls));
                touch("UDP6", ls, "*", "listen", e.dwOwningPid, false, 0, 0);
            }
            break;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER) break;
    }

    estatsTried_ = true;
    estatsWorked_ = estatsWorked_ || estatsOk;

    constexpr size_t kCap = 8000;
    if (log_.size() > kCap) {
        std::sort(log_.begin(), log_.end(), [](const ConnRecord& a, const ConnRecord& b) {
            if (a.active != b.active) return a.active > b.active;
            return a.lastSeen > b.lastSeen;
        });
        log_.resize(kCap);
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
    ConnectionConfig& cfg = ctx.project.connection;
    if (apiProjectHash_ != ctx.project.hash) {
        apiProjectHash_ = ctx.project.hash;
        std::snprintf(apiTokenBuf_, sizeof(apiTokenBuf_), "%s", cfg.accessToken.c_str());
    }

    ImGui::SeparatorText("Local API");
    bool enabled = cfg.enabled;
    if (ImGui::Checkbox("Enabled", &enabled)) cfg.enabled = enabled;
    ImGui::SameLine();
    bool localOnly = cfg.localhostOnly;
    if (ImGui::Checkbox("Localhost only", &localOnly)) cfg.localhostOnly = localOnly;
    ImGui::SameLine();
    bool auth = cfg.authEnabled;
    if (ImGui::Checkbox("Auth", &auth)) cfg.authEnabled = auth;
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.0f * theme::UiScale());
    if (ImGui::InputTextWithHint("##apitoken", "per-project token", apiTokenBuf_, sizeof(apiTokenBuf_)))
        cfg.accessToken = apiTokenBuf_;

    std::string cfgErr;
    if (!ValidateConnectionConfig(cfg, &cfgErr))
        ImGui::TextColored(theme::col::bad(), "%s", cfgErr.c_str());
    else if (cfg.enabled)
        ImGui::TextColored(theme::col::warn(), "Framework armed; listener implementation is a follow-up.");
    else
        ImGui::TextDisabled("Disabled by default. Schema/event timeline are available for future local transports.");

    if (ImGui::TreeNodeEx("Event timeline", ImGuiTreeNodeFlags_DefaultOpen,
                          "Event timeline (%d)", (int)ctx.project.connectionEvents.size())) {
        ImGui::TextDisabled("Paste a schema message to validate and append it to the project timeline.");
        ImGui::InputTextMultiline("##apievent", apiEventBuf_, sizeof(apiEventBuf_),
                                  ImVec2(-1.0f, 96.0f * theme::UiScale()));
        if (ImGui::Button("Validate + append")) {
            ConnectionEnvelope ev;
            std::string err;
            if (DeserializeConnectionEnvelope(apiEventBuf_, ev, &err)) {
                ctx.project.connectionEvents.push_back(std::move(ev));
                if (ctx.project.connectionEvents.size() > 512)
                    ctx.project.connectionEvents.erase(ctx.project.connectionEvents.begin(),
                                                       ctx.project.connectionEvents.begin() +
                                                       (ctx.project.connectionEvents.size() - 512));
                apiStatus_ = "accepted";
            } else {
                apiStatus_ = err;
            }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear events")) ctx.project.connectionEvents.clear();
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
            for (int i = (int)ctx.project.connectionEvents.size() - 1; i >= 0; --i) {
                const ConnectionEnvelope& e = ctx.project.connectionEvents[(size_t)i];
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

    ImGui::TextColored(theme::col::accent(), "Network activity \xE2\x80\x94 live connections + history");
    ImGui::SameLine();
    ImGui::TextDisabled("who is talking to where, and how much data is moving");

    renderLocalApiFramework(ctx);
    ImGui::Separator();

    // The debugged process: native Win32 debugger PID, else the JDWP-injected PID.
    DbgSnapshot dbg = ctx.debug.snapshot();
    const uint32_t attachedPid = dbg.attached() ? dbg.pid : ctx.jdwpTargetPid;

    if (ImGui::Button("Refresh now")) pollAllConnections();
    ImGui::SameLine(); ImGui::Checkbox("Auto", &auto_);
    ImGui::SameLine(); ImGui::Checkbox("Active only", &activeOnly_);
    ImGui::SameLine(); ImGui::Checkbox("TCP only", &tcpOnly_);
    ImGui::SameLine();
    ImGui::BeginDisabled(attachedPid == 0);
    ImGui::Checkbox("Attached process only", &attachedOnly_);
    ImGui::EndDisabled();
    if (attachedPid && ImGui::IsItemHovered())
        ImGui::SetTooltip("Show only connections owned by the debugged process (PID %u)", attachedPid);
    ImGui::SameLine(); if (ImGui::Button("Clear history")) log_.clear();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.0f * scale);
    ui::SearchBox("##connfilter", "filter ip / port / process...", filter_, sizeof(filter_), -1.0f);
    if (attachedPid == 0) attachedOnly_ = false;   // nothing attached: don't hide everything

    if (auto_) {
        ctx.wantContinuousRedraw = true;
        if (log_.empty() || (uint32_t)(now - lastPollTick_) > 1000) pollAllConnections();
    }

    if (estatsTried_ && !estatsWorked_)
        ImGui::TextColored(theme::col::muted(),
            "Byte/rate columns need TCP ESTATS \xE2\x80\x94 run the disassembler as Administrator to populate them.");

    std::string needle = filter_;
    for (char& c : needle) c = (char)std::tolower((unsigned char)c);
    auto matches = [&](const ConnRecord& r) {
        if (activeOnly_ && !r.active) return false;
        if (tcpOnly_ && r.proto.rfind("TCP", 0) != 0) return false;
        if (attachedOnly_ && attachedPid && r.pid != attachedPid) return false;
        if (needle.empty()) return true;
        std::string hay = r.proc + ' ' + r.local + ' ' + r.remote + ' ' + r.proto + ' ' + r.state;
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
    ImGui::TextDisabled("%d shown / %zu tracked \xC2\xB7 %d active", (int)view.size(), log_.size(), activeCount);

    // When a payload capture is possible (native debugger attached), split the
    // tab: connections on top, the live send/recv payload viewer below.
    const bool canCapture = dbg.attached();
    const float tableH = canCapture ? ImGui::GetContentRegionAvail().y * 0.45f
                                     : ImGui::GetContentRegionAvail().y;
    if (ImGui::BeginTable("conn_tbl", 9,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_Resizable, ImVec2(0, tableH))) {
        ImGui::TableSetupScrollFreeze(0, 1);
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
    if (log_.empty())
        ImGui::TextDisabled("No connections sampled yet \xE2\x80\x94 click Refresh, or leave Auto on.");

    if (canCapture) renderPayloadCapture(ctx);
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

void ConnectionsTab::renderPayloadCapture(AppContext& ctx) {
    const float scale = theme::UiScale();
    ImGui::Separator();
    bool on = ctx.debug.netTapEnabled();
    if (ImGui::Checkbox("Capture payloads (read send/recv data of the debugged process)", &on))
        ctx.debug.enableNetTap(on);
    ImGui::SameLine();
    if (ImGui::SmallButton("Clear##caps")) { ctx.debug.clearNetCaptures(); caps_.clear(); capCount_ = 0; capSel_ = -1; }
    ImGui::SameLine(); ImGui::Checkbox("Hex##caps", &capHex_);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200.0f * scale);
    ui::SearchBox("##capfilter", "filter payload text...", capFilter_, sizeof(capFilter_), -1.0f);
    ImGui::SameLine();
    const bool logging = ctx.debug.netCaptureLogEnabled();
    if (ImGui::SmallButton(logging ? "Stop file log##caps" : "Start file log...##caps")) {
        if (logging) {
            ctx.debug.closeNetCaptureLogFile();
            capLogStatus_ = "Network payload log stopped.";
            ui::Toast(ui::ToastKind::Info, capLogStatus_);
        } else {
            std::string path;
            if (choosePayloadLogFile(path)) {
                std::string err;
                if (ctx.debug.setNetCaptureLogFile(path, /*append=*/false, &err)) {
                    ctx.debug.enableNetTap(true);
                    on = true;
                    capLogStatus_ = "Logging network payloads to " + path;
                    ui::Toast(ui::ToastKind::Success, "Network payload logging started");
                } else {
                    capLogStatus_ = "Log start failed: " + err;
                    ui::Toast(ui::ToastKind::Error, capLogStatus_);
                }
            }
        }
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Write every captured send/recv buffer to a text log with printable text and exact hex bytes.");
    if (ctx.debug.netCaptureLogEnabled()) {
        std::string path = ctx.debug.netCaptureLogPath();
        ImGui::TextColored(theme::col::good(), "Logging to file");
        if (!path.empty()) {
            ImGui::SameLine();
            ImGui::TextDisabled("%s", path.c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Copy path##caplog")) ImGui::SetClipboardText(path.c_str());
        }
    } else if (!capLogStatus_.empty()) {
        ImGui::TextDisabled("%s", capLogStatus_.c_str());
    }
    if (!on) {
        ImGui::TextDisabled("Hooks ws2_32 send/recv/WSASend/WSARecv in the attached process and logs each buffer.");
        ImGui::TextDisabled("Plaintext (HTTP/JSON) is readable; TLS/HTTPS shows as encrypted bytes. x64 targets only.");
        return;
    }
    ctx.wantContinuousRedraw = true;   // stream captures live

    // Refetch only when new captures arrived (the buffers are large to copy).
    size_t total = ctx.debug.netCaptureCount();
    if (total != capCount_) { caps_ = ctx.debug.netCaptures(); capCount_ = total; }

    std::string needle = capFilter_;
    for (char& c : needle) c = (char)std::tolower((unsigned char)c);
    std::vector<int> view;
    view.reserve(caps_.size());
    for (int i = (int)caps_.size() - 1; i >= 0; --i) {     // newest first
        if (!needle.empty()) {
            std::string t = toText(caps_[i].bytes);
            for (char& c : t) c = (char)std::tolower((unsigned char)c);
            if (t.find(needle) == std::string::npos) continue;
        }
        view.push_back(i);
    }
    ImGui::TextDisabled("%zu captured \xC2\xB7 %d shown", caps_.size(), (int)view.size());

    const float listW = 320.0f * scale;
    ImGui::BeginChild("cap_list", ImVec2(listW, 0), ImGuiChildFlags_Borders);
    ImGuiListClipper clip;
    clip.Begin((int)view.size());
    while (clip.Step()) {
        for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
            const NetCapture& c = caps_[view[row]];
            ImGui::PushID(view[row]);
            std::string preview = toText(c.bytes);
            for (char& ch : preview) if (ch == '\n') ch = ' ';
            if (preview.size() > 40) preview.resize(40);
            char head[80];
            std::snprintf(head, sizeof(head), "%s %uB", c.dir == 0 ? "\xE2\x86\x91send" : "\xE2\x86\x93recv", c.total);
            const bool sel = (capSel_ == view[row]);
            if (ImGui::Selectable(head, sel)) capSel_ = view[row];
            ImGui::SameLine();
            ImGui::TextColored(theme::col::muted(), "%s", preview.c_str());
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
    ImGui::SameLine();

    ImGui::BeginChild("cap_detail", ImVec2(0, 0), ImGuiChildFlags_Borders);
    if (capSel_ >= 0 && capSel_ < (int)caps_.size()) {
        const NetCapture& c = caps_[capSel_];
        ImGui::Text("%s  sock=0x%llX  tid=%u  %u bytes%s",
                    c.dir == 0 ? "SEND (outgoing)" : "RECV (incoming)",
                    (unsigned long long)c.sock, c.tid, c.total,
                    c.bytes.size() < c.total ? "  (truncated to capture limit)" : "");
        std::string body = (capHex_ || !mostlyText(c.bytes)) ? toHexDump(c.bytes) : toText(c.bytes);
        ImGui::SameLine();
        if (ImGui::SmallButton("Copy##capbody")) ImGui::SetClipboardText(body.c_str());
        if (!capHex_ && mostlyText(c.bytes) &&
            (c.bytes.size() && (c.bytes[0] == '{' || c.bytes[0] == '[')))
            ImGui::TextColored(theme::col::accent(), "looks like JSON");
        ui::PushMono();
        ImGui::InputTextMultiline("##capbody", body.data(), body.size() + 1,
                                  ImVec2(-1, -1), ImGuiInputTextFlags_ReadOnly);
        ui::PopMono();
    } else {
        ImGui::TextDisabled("Select a captured buffer on the left to read it.");
    }
    ImGui::EndChild();
}

} // namespace ds
