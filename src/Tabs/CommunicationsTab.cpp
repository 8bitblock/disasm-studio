#include "CommunicationsTab.h"
// Winsock headers must precede windows.h; iphlpapi gives the per-PID conn tables.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "../Core/JvmAttach.h"
#include "../Disasm/JvmDisassembler.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"
#include <algorithm>
#include <cctype>
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

    // Size-then-fetch with a bounded retry: the table can grow between the size
    // query and the fetch, in which case the fetch returns ERROR_INSUFFICIENT_BUFFER
    // with `sz` updated — retry with the larger buffer instead of silently dropping.
    std::vector<uint8_t> buf;
    DWORD sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    for (int attempt = 0; sz && attempt < 3; ++attempt) {
        buf.assign(sz, 0);
        DWORD rc = GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc == NO_ERROR) {
            auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                const auto& r = t->table[i];
                if (r.dwOwningPid != pid) continue;
                char ls[64], rs[64];
                fmtEndpoint(r.dwLocalAddr, r.dwLocalPort, ls, sizeof(ls));
                fmtEndpoint(r.dwRemoteAddr, r.dwRemotePort, rs, sizeof(rs));
                conns_.push_back({ std::string(ls) + "  ->  " + rs, "TCP", tcpStateName(r.dwState) });
            }
            break;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER) break;   // sz was updated; loop reallocates
    }
    sz = 0;
    GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    for (int attempt = 0; sz && attempt < 3; ++attempt) {
        buf.assign(sz, 0);
        DWORD rc = GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (rc == NO_ERROR) {
            auto* u = reinterpret_cast<MIB_UDPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < u->dwNumEntries; ++i) {
                const auto& r = u->table[i];
                if (r.dwOwningPid != pid) continue;
                char ls[64];
                fmtEndpoint(r.dwLocalAddr, r.dwLocalPort, ls, sizeof(ls));
                conns_.push_back({ ls, "UDP", "listening" });
            }
            break;
        }
        if (rc != ERROR_INSUFFICIENT_BUFFER) break;   // sz was updated; loop reallocates
    }
}

void CommunicationsTab::renderProcesses(AppContext& ctx) {
    ImGui::SeparatorText("Native Processes");
    if (ui::ToolbarIconButton(DS_ICON_REFRESH, "Refresh", "Re-enumerate running processes") || !enumerated_) {
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
    ui::SearchBox("##pfilter", "filter by name...", filter_, sizeof(filter_), 220.0f * theme::UiScale());
    ImGui::SameLine();
    ImGui::TextDisabled("%d process(es)", (int)procs_.size());

    DbgSnapshot snap = ctx.debug.snapshot();
    if (snap.attached()) {
        ImGui::SameLine();
        char b[40]; std::snprintf(b, sizeof(b), "debugging PID %u", snap.pid);
        ui::Badge(b, theme::col::good());
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
                    ui::Toast(ui::ToastKind::Error, "Attach failed: " + err);
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
        // Small hero (no button) bounded to this section's slot, so the HvDbg
        // panel below keeps its place; the process list to the left is the action.
        ImGui::BeginChild("conn_none", ImVec2(0, ImGui::GetContentRegionAvail().y * 0.55f));
        ui::EmptyState(DS_ICON_NETWORK, "No process selected",
                       "Select a process to list its live TCP/UDP connections.");
        ImGui::EndChild();
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

    const char* st = "detached";
    if (snap.state == JdwpState::Running)   st = "running";
    if (snap.state == JdwpState::Suspended) st = "suspended";
    if (snap.state == JdwpState::Dead)      st = "connection lost";
    char hdr[192];
    std::snprintf(hdr, sizeof(hdr), "Java debug (JDWP) \xE2\x80\x94 %s%s%s###jdwp_hdr",
                  st, snap.vmName.empty() ? "" : ", ", snap.vmName.c_str());
    if (!ImGui::CollapsingHeader(hdr, snap.attached() ? ImGuiTreeNodeFlags_DefaultOpen : 0))
        return;

    // Housekeeping shared by both attach paths: clear stale per-session UI state.
    auto onAttached = [&] {
        jdwpStatus_.clear();
        jdwpSelClass_ = jdwpInsnsClass_ = jdwpInsnsMethod_ = jdwpCpClass_ = 0;
        jdwpMethods_.clear();
        jdwpInsns_.clear();
        jdwpCp_.reset();
        jdwpSeenStopClass_ = jdwpSeenStopMethod_ = 0;
        jdwpSeenStopBci_ = ~0ull;
    };

    if (!snap.attached()) {
        jdwpPort_ = jdwpPort_ < 1 ? 1 : jdwpPort_ > 65535 ? 65535 : jdwpPort_;

        // --- Primary path: inject the JDWP agent into a RUNNING JVM (no -agentlib
        //     prelaunch flag). Operates on the process selected in the list below. ---
        ImGui::SeparatorText("Attach to a running Java process");
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
            ImGui::TextDisabled("Select a process in the list below, then attach here. No JVM debug flags needed.");
        } else {
            ImGui::Text("Selected: %s (PID %u)", selName.c_str(), selPid);
            ImGui::SameLine();
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
                // The button is gated to a HotSpot x64 target, so the agent may be
                // listening for several reasons: it just loaded (ok), the request was
                // accepted but unconfirmed (enqueued), or it was "already loaded" from
                // a prior attempt (refused now, but still bound). So always TRY the
                // socket; the connect is the real proof. Show the VM's reason if not.
                std::string err, lastErr;
                bool connected = false;
                for (int tries = 0; tries < 8 && !connected; ++tries) {
                    if (ctx.jdwp.attach("127.0.0.1", (uint16_t)jdwpPort_, err)) connected = true;
                    else { lastErr = err; ::Sleep(300); }   // agent may need a moment to bind
                }
                if (connected) {
                    onAttached();
                    ctx.jdwpTargetPid = selPid;   // scope the Connections "attached only" view
                    // Freeze the VM immediately so the launcher's Java main logic can be
                    // breakpointed before it runs on. The agent stays suspend=n (no frozen
                    // orphan if the connect had failed); one Resume releases this cleanly.
                    if (jdwpSuspendOnAttach_) ctx.jdwp.suspendAll();
                    ui::Toast(ui::ToastKind::Success,
                              std::string("Attached to JVM PID ") + std::to_string(selPid) +
                              (jdwpSuspendOnAttach_ ? " (suspended)" : ""));
                } else {
                    jdwpStatus_ = (ar.ok ? std::string("agent loaded") : ar.error) +
                                  "  \xE2\x80\x94 connect failed: " + lastErr;
                    if (!ar.agentOutput.empty()) jdwpStatus_ += "\nVM said: " + ar.agentOutput;
                    ui::Toast(ui::ToastKind::Error, "JVM attach failed (details in the Java debug panel)");
                }
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            ImGui::SetNextItemWidth(80.0f * scale);
            ImGui::InputInt("port##jdwpinj", &jdwpPort_, 0, 0);
            ImGui::SameLine();
            ImGui::Checkbox("Suspend on attach##jdwpsusp", &jdwpSuspendOnAttach_);
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("Freeze every Java thread the instant we connect, so you can set\n"
                                  "breakpoints in the launcher's main logic before it runs on.\n"
                                  "Click Resume to let it continue. Recommended for EXE launchers\n"
                                  "that hand off to an embedded JVM.");
            if (ji.flavor == JvmFlavor::OpenJ9)
                ImGui::TextColored(theme::col::warn(), "OpenJ9 uses a different attach protocol \xE2\x80\x94 launch with -agentlib:jdwp and use the host:port connect below.");
            else if (ji.flavor == JvmFlavor::HotSpot && !ji.is64)
                ImGui::TextColored(theme::col::warn(), "32-bit JVM: injection needs a 64-bit target (debug it natively via Attach in the list).");
            else if (ji.flavor == JvmFlavor::None)
                ImGui::TextDisabled("This process has no jvm.dll loaded. Pick a java/javaw process (or one embedding a JVM).");
            else
                ImGui::TextDisabled("Loads the JDWP agent into the live VM, then connects \xE2\x80\x94 no restart, no launch flags.");
        }

        // --- Secondary path: connect to an agent that is ALREADY listening
        //     (remote target, or a VM launched with -agentlib:jdwp). ---
        ImGui::SeparatorText("Or connect to a listening JDWP agent");
        ImGui::SetNextItemWidth(150.0f * scale);
        ImGui::InputText("##jdwphost", jdwpHost_, sizeof(jdwpHost_));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(90.0f * scale);
        ImGui::InputInt("##jdwpport", &jdwpPort_, 0, 0);
        jdwpPort_ = jdwpPort_ < 1 ? 1 : jdwpPort_ > 65535 ? 65535 : jdwpPort_;
        ImGui::SameLine();
        if (ImGui::Button("Connect##jdwp")) {
            std::string err;
            if (ctx.jdwp.attach(jdwpHost_, (uint16_t)jdwpPort_, err)) {
                onAttached();
                if (jdwpSuspendOnAttach_) ctx.jdwp.suspendAll();
            } else jdwpStatus_ = err;
        }
        ImGui::SameLine();
        ImGui::TextDisabled("host:port of a VM started with -agentlib:jdwp=...,server=y,address=*:%d", jdwpPort_);
        if (!jdwpStatus_.empty()) ImGui::TextColored(theme::col::bad(), "%s", jdwpStatus_.c_str());
        return;
    }

    // ---- control strip ------------------------------------------------------
    const bool suspended = snap.state == JdwpState::Suspended;
    if (suspended) {
        if (ImGui::Button("Resume##jdwp")) ctx.jdwp.resumeAll();
        ImGui::SameLine();
        if (ImGui::Button("Step Into##jdwp")) ctx.jdwp.stepInto();
        ImGui::SameLine();
        if (ImGui::Button("Step Over##jdwp")) ctx.jdwp.stepOver();
        ImGui::SameLine();
        if (ImGui::Button("Step Out##jdwp")) ctx.jdwp.stepOut();
    } else {
        if (ImGui::Button("Suspend##jdwp")) ctx.jdwp.suspendAll();
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh classes##jdwp")) ctx.jdwp.refreshClasses();
    ImGui::SameLine();
    if (ImGui::Button("Detach##jdwp")) {
        ctx.jdwp.detach();
        ctx.jdwpTargetPid = 0;
        return;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%s%s%s \xC2\xB7 %s", snap.vmName.c_str(),
                        snap.vmVersion.empty() ? "" : " ",
                        snap.vmVersion.c_str(), snap.lastEvent.c_str());
    if (!jdwpStatus_.empty()) ImGui::TextColored(theme::col::bad(), "%s", jdwpStatus_.c_str());

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
    ImGui::BeginChild("jdwp_body", ImVec2(0, 380.0f * scale), ImGuiChildFlags_Borders);
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

                char line[512];
                std::snprintf(line, sizeof(line), "%c%5llu:  %-14s %-24s%s%s",
                              isStopRow ? '>' : hasBp ? '*' : ' ',
                              (unsigned long long)in.address,
                              in.mnemonic.c_str(), in.operands.c_str(),
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

void CommunicationsTab::render(AppContext& ctx) {
    // Java debug (JDWP) console: full-width, collapsible, above the native panes.
    // (System-wide connection monitoring with history lives in the Connections tab.)
    renderJdwp(ctx);
    ImGui::Spacing();
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
