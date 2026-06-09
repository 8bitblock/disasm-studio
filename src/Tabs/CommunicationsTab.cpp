#include "CommunicationsTab.h"
// Winsock headers must precede windows.h; iphlpapi gives the per-PID conn tables.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "imgui.h"
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace ds {

static void fmtEndpoint(unsigned long addr, unsigned long port, char* out, size_t n) {
    struct in_addr a; a.S_un.S_addr = (ULONG)addr;
    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &a, ip, sizeof(ip));
    std::snprintf(out, n, "%s:%u", ip, (unsigned)ntohs((u_short)port));
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

// Enumerate the IPv4 TCP/UDP endpoints owned by `pid` (IP Helper API).
void CommunicationsTab::refreshConnections(uint32_t pid) {
    conns_.clear();
    connsForPid_ = pid;
    if (!pid) return;

    std::vector<uint8_t> buf;
    DWORD sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (sz) {
        buf.assign(sz, 0);
        if (GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                if (r.dwOwningPid != pid) continue;
                char ls[64], rs[64];
                fmtEndpoint(r.dwLocalAddr, r.dwLocalPort, ls, sizeof(ls));
                fmtEndpoint(r.dwRemoteAddr, r.dwRemotePort, rs, sizeof(rs));
                conns_.push_back({ std::string(ls) + "  ->  " + rs, "TCP", tcpStateName(r.dwState) });
            }
        }
    }
    sz = 0;
    GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (sz) {
        buf.assign(sz, 0);
        if (GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            auto* u = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < u->dwNumEntries; ++i) {
                const auto& r = u->table[i];
                if (r.dwOwningPid != pid) continue;
                char ls[64];
                fmtEndpoint(r.dwLocalAddr, r.dwLocalPort, ls, sizeof(ls));
                conns_.push_back({ ls, "UDP", "listening" });
            }
        }
    }
}

void CommunicationsTab::renderProcesses(AppContext& ctx) {
    ImGui::SeparatorText("Native Processes");
    if (ImGui::Button("Refresh") || !enumerated_) {
        // The selection follows the PID, not the row index: re-enumerating + re-sorting
        // would otherwise leave selProc_ pointing at a different process, so its
        // modules/connections would be listed for the wrong PID.
        uint32_t prevPid = (selProc_ >= 0 && selProc_ < (int)procs_.size()) ? procs_[selProc_].pid : 0;
        procs_ = pm_.enumerate();
        enumerated_ = true;
        // Stable, readable ordering by name.
        std::sort(procs_.begin(), procs_.end(),
                  [](const ProcessInfo& a, const ProcessInfo& b){ return a.name < b.name; });
        selProc_ = -1;
        if (prevPid)
            for (int i = 0; i < (int)procs_.size(); ++i)
                if (procs_[i].pid == prevPid) { selProc_ = i; break; }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##pfilter", "filter by name...", filter_, sizeof(filter_));
    ImGui::SameLine();
    ImGui::Text("%d process(es)", (int)procs_.size());

    DbgSnapshot snap = ctx.debug.snapshot();
    if (snap.attached()) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.4f,0.9f,0.4f,1), "| debugging PID %u", snap.pid);
    }
    if (!status_.empty()) ImGui::TextDisabled("%s", status_.c_str());

    // Fill the remaining height so the list only scrolls when truly overflowing.
    if (ImGui::BeginTable("procs", 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_Resizable, ImVec2(0, ImGui::GetContentRegionAvail().y))) {
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Process");
        ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)procs_.size(); ++i) {
            auto& p = procs_[i];
            if (filter_[0] && p.name.find(filter_) == std::string::npos) continue;
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(0); ImGui::Text("%u", p.pid);
            ImGui::TableSetColumnIndex(1);
            if (ImGui::Selectable(p.name.c_str(), selProc_ == i,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap))
                selProc_ = i;
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(p.is64 ? "x64" : "x86");
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(p.canOpen ? ImVec4(0.6f,0.8f,0.6f,1) : ImVec4(0.8f,0.5f,0.5f,1),
                               "%s", p.canOpen ? "ok" : "denied");
            ImGui::TableSetColumnIndex(4);
            bool isAttached = snap.attached() && snap.pid == p.pid;
            if (isAttached) {
                if (ImGui::SmallButton("Detach")) { ctx.debug.detach(); status_ = "detached"; }
            } else if (ImGui::SmallButton("Attach")) {
                std::string err;
                if (ctx.debug.attach(p.pid, err)) {
                    status_ = "debugging " + p.name + " (PID " + std::to_string(p.pid) + ")";
                    // No file backs this session: point the engine/arch at the debuggee's
                    // bitness so generic ctx.disasm / ctx.arch fallbacks decode correctly.
                    // (When a file IS loaded its arch is authoritative for the static view,
                    // and live paths use liveDecoder(snap.is32) — so don't touch it then.)
                    if (!ctx.binary.loaded()) {
                        ctx.arch = ctx.debug.snapshot().is32 ? Arch::X86 : Arch::X64;
                        ctx.rebuildDisassembler();
                    }
                    ctx.openLiveAssemblyView();
                } else {
                    status_ = err;
                }
            }
            ImGui::PopID();
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
    if (pid != modsForPid_) { mods_ = pm_.modules(pid); modsForPid_ = pid; }

    ImGui::Text("%s (PID %u) - %d module(s)", procs_[selProc_].name.c_str(), pid, (int)mods_.size());
    if (ImGui::BeginTable("mods", 3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
            ImVec2(0, ImGui::GetContentRegionAvail().y * 0.6f))) {
        ImGui::TableSetupColumn("Module");
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableHeadersRow();
        for (auto& m : mods_) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(m.name.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)m.base);
            ImGui::TableSetColumnIndex(2); ImGui::Text("%llu KB", (unsigned long long)(m.size / 1024));
        }
        ImGui::EndTable();
    }
    if (mods_.empty())
        ImGui::TextDisabled("No modules (need matching bitness / rights; try as Administrator).");
}

void CommunicationsTab::renderConnections() {
    ImGui::SeparatorText("Connections (selected process)");
    uint32_t pid = (selProc_ >= 0 && selProc_ < (int)procs_.size()) ? procs_[selProc_].pid : 0;
    if (!pid) {
        ImGui::TextDisabled("Select a process to list its live TCP/UDP connections.");
        return;
    }
    if (pid != connsForPid_) refreshConnections(pid);
    ImGui::Text("%s (PID %u) - %d endpoint(s)", procs_[selProc_].name.c_str(), pid, (int)conns_.size());
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh##conn")) refreshConnections(pid);

    if (ImGui::BeginTable("conns", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
                          ImVec2(0, ImGui::GetContentRegionAvail().y * 0.8f))) {
        ImGui::TableSetupColumn("Endpoint");
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 110);
        ImGui::TableHeadersRow();
        for (auto& c : conns_) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(c.endpoint.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", c.type.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%s", c.state.c_str());
        }
        ImGui::EndTable();
    }
    if (conns_.empty()) ImGui::TextDisabled("No active IPv4 TCP/UDP endpoints for this process.");
}

// AMD-V (SVM) hypervisor debugging channel. The kernel driver (driver/HvDbg.sys)
// creates \\.\HvDbg; here we open it, handshake, and surface its state. When the
// driver isn't loaded this degrades to an informational "not present" panel.
void CommunicationsTab::renderHvDbg() {
    ImGui::SeparatorText("AMD-V Hypervisor (\\\\.\\HvDbg)");

    const bool connected = hv_.connected();
    ImVec4 dot = connected ? ImVec4(0.45f, 0.85f, 0.45f, 1.0f) : ImVec4(0.65f, 0.65f, 0.65f, 1.0f);
    ImGui::TextColored(dot, connected ? "[connected]" : "[not connected]");
    ImGui::SameLine();
    if (ImGui::SmallButton(connected ? "Reconnect" : "Connect")) {
        hv_.disconnect();
        hvHave_ = false; hvAbiMismatch_ = false;
        if (hv_.connect() && hv_.ping(hvInfo_)) {
            hvHave_ = true;
            // ping() returns true even on an ABI mismatch, leaving the warning in
            // lastError(); surface it rather than reporting a clean handshake.
            hvAbiMismatch_ = !hv_.lastError().empty();
            hvStatus_ = hvAbiMismatch_ ? hv_.lastError() : "Handshake OK.";
        } else hvStatus_ = hv_.lastError();
    }
    if (connected) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Refresh##hv")) {
            if (hv_.getState(hvInfo_)) { hvHave_ = true; hvStatus_ = "State refreshed."; }
            else hvStatus_ = hv_.lastError();
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Disconnect")) { hv_.disconnect(); hvHave_ = false; hvAbiMismatch_ = false; hvStatus_ = "Disconnected."; }
    }

    // Driver lifecycle (SCM): register + start HvDbg.sys so \\.\HvDbg exists, or
    // stop + deregister it. Requires elevation; greys out when not admin.
    {
        if (!hvStateValid_) { hvState_ = hvLoader_.state(); hvStateValid_ = true; }  // SCM query: cached, refreshed on action
        const HvDbgLoader::State ls = hvState_;
        const bool installed = (ls != HvDbgLoader::State::NotInstalled && ls != HvDbgLoader::State::Unknown);
        const char* lbl = ls == HvDbgLoader::State::Running     ? "[driver running]"
                        : ls == HvDbgLoader::State::Stopped     ? "[driver installed]"
                        : ls == HvDbgLoader::State::NotInstalled? "[driver not loaded]"
                                                                : "[driver state unknown]";
        ImVec4 lc = ls == HvDbgLoader::State::Running ? ImVec4(0.45f, 0.85f, 0.45f, 1.0f)
                                                      : ImVec4(0.70f, 0.70f, 0.50f, 1.0f);
        ImGui::TextColored(lc, "%s", lbl);
        ImGui::SameLine();

        if (hvElevated_ < 0) hvElevated_ = HvDbgLoader::isElevated() ? 1 : 0;  // never changes for this process
        const bool elevated = hvElevated_ != 0;
        if (!elevated) ImGui::BeginDisabled();
        if (!installed) {
            if (ImGui::SmallButton("Load driver")) {
                hvStateValid_ = false;   // re-query the SCM state after the attempt
                if (hvLoader_.load()) {
                    hvStatus_ = "HvDbg.sys loaded - click Connect to attach.";
                    if (hv_.connect() && hv_.ping(hvInfo_)) {
                        hvHave_ = true;
                        hvAbiMismatch_ = !hv_.lastError().empty();
                        if (hvAbiMismatch_) hvStatus_ = hv_.lastError(); // rebuild-driver warning wins
                    }
                } else hvStatus_ = hvLoader_.lastError();
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Register + start HvDbg.sys (next to the exe) via the SCM.");
        } else {
            if (ImGui::SmallButton("Unload driver")) {
                hvStateValid_ = false;   // re-query the SCM state after the attempt
                hv_.disconnect(); hvHave_ = false; hvAbiMismatch_ = false;
                hvStatus_ = hvLoader_.unload() ? "HvDbg.sys stopped and deregistered."
                                               : hvLoader_.lastError();
            }
        }
        if (!elevated) {
            ImGui::EndDisabled();
            ImGui::SameLine();
            ImGui::TextDisabled("(run as Administrator to load/unload)");
        }
    }

    if (hvHave_) {
        const HVDBG_INFO& i = hvInfo_;
        ImGui::Text("Driver v%u.%u  |  ABI %u  |  CPU %.16s",
                    (i.driverVersion >> 16) & 0xFFFF, i.driverVersion & 0xFFFF, i.abiVersion, i.vendor);
        auto cap = [](bool on, const char* yes, const char* no) {
            ImGui::SameLine(); ImGui::TextColored(on ? ImVec4(0.45f, 0.85f, 0.45f, 1.0f)
                                                     : ImVec4(0.70f, 0.55f, 0.45f, 1.0f), "%s", on ? yes : no);
        };
        ImGui::TextUnformatted("SVM:");          cap(i.flags & HVDBG_FLAG_SVM_SUPPORTED, "supported", "unsupported");
        ImGui::SameLine(); ImGui::TextUnformatted(" NPT:"); cap(i.flags & HVDBG_FLAG_NPT_SUPPORTED, "yes", "no");
        ImGui::SameLine(); ImGui::TextUnformatted(" Active:"); cap(i.flags & HVDBG_FLAG_ACTIVE, "yes", "no");
        if (i.flags & HVDBG_FLAG_SVM_LOCKED_OFF)
            ImGui::TextColored(ImVec4(0.85f, 0.5f, 0.4f, 1.0f), "SVM is disabled+locked in firmware - enable SVM in BIOS.");
        if (i.flags & HVDBG_FLAG_HV_PRESENT)
            ImGui::TextColored(ImVec4(0.85f, 0.7f, 0.4f, 1.0f), "Another hypervisor is present (Hyper-V/HVCI may own SVM).");
        ImGui::Text("Virtualized %u / %u CPU(s)   |   #VMEXIT serviced: %llu",
                    i.virtualizedCount, i.cpuCount, (unsigned long long)i.vmexitCount);

        const bool active = (i.flags & HVDBG_FLAG_ACTIVE) != 0;
        if (hvAbiMismatch_) {
            // The HVDBG_INFO wire layout is what abiVersion guards; don't drive
            // machine-wide VMRUN IOCTLs against a driver whose ABI we don't match.
            ImGui::TextColored(ImVec4(0.85f, 0.5f, 0.4f, 1.0f),
                               "ABI mismatch - rebuild the driver before virtualizing.");
        } else if (!active) {
            if (ImGui::Button("Virtualize all CPUs")) {
                if (hv_.virtualize() && hv_.getState(hvInfo_)) hvStatus_ = "VMRUN active.";
                else hvStatus_ = hv_.lastError();
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Enables EFER.SVME and runs VMRUN on every logical CPU (kernel driver).");
        } else {
            if (ImGui::Button("Devirtualize")) {
                if (hv_.devirtualize() && hv_.getState(hvInfo_)) hvStatus_ = "Hypervisor torn down.";
                else hvStatus_ = hv_.lastError();
            }
        }
    } else {
        ImGui::TextDisabled("The \\\\.\\HvDbg channel is served by the AMD-V (SVM) driver in driver/.");
        ImGui::TextDisabled("Click \"Load driver\" (admin + signed/test-signing) then Connect to attach.");
    }
    if (!hvStatus_.empty()) ImGui::TextColored(ImVec4(0.6f, 0.7f, 0.85f, 1.0f), "%s", hvStatus_.c_str());
}

void CommunicationsTab::render(AppContext& ctx) {
    ImVec2 avail = ImGui::GetContentRegionAvail();
    ImGui::BeginChild("c_proc", ImVec2(avail.x * 0.55f - 4, 0), ImGuiChildFlags_Borders);
    renderProcesses(ctx);
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("c_right", ImVec2(0, 0), ImGuiChildFlags_Borders);
    renderModules();
    ImGui::Spacing();
    renderConnections();
    ImGui::Spacing();
    renderHvDbg();
    ImGui::EndChild();
}

} // namespace ds
