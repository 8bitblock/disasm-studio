#pragma once
#include "ITab.h"
#include "../Core/ProcessManager.h"
#include "../Hv/HvDbgClient.h"
#include "../Hv/HvDbgLoader.h"
#include "../Hv/HvDbgProtocol.h"
#include <string>
#include <vector>

namespace ds {

// Communications tab: native-process side. Real Win32 process enumeration and
// attach (debug API), module listing for the selected process, plus the
// connections/channels model used to talk to external agents/drivers.
class CommunicationsTab final : public ITab {
public:
    const char* name() const override { return "Communications"; }
    void render(AppContext& ctx) override;

private:
    void renderProcesses(AppContext& ctx);
    void renderModules();
    void renderConnections();
    void renderHvDbg();                       // AMD-V (SVM) hypervisor channel: \\.\HvDbg
    void refreshConnections(uint32_t pid);   // live TCP/UDP endpoints owned by pid

    struct Conn { std::string endpoint; std::string type; std::string state; };

    ProcessManager           pm_;
    std::vector<ProcessInfo> procs_;
    std::vector<ModuleInfo>  mods_;
    bool                     enumerated_ = false;
    int                      selProc_    = -1;
    uint32_t                 modsForPid_ = 0;
    std::string              status_;

    std::vector<Conn>        conns_;          // live per-process connections
    uint32_t                 connsForPid_ = 0;
    char filter_[64] = "";

    // AMD-V (SVM) hypervisor backend (\\.\HvDbg).
    HvDbgClient              hv_;
    HvDbgLoader              hvLoader_;          // SCM-driven load/unload of HvDbg.sys
    HVDBG_INFO               hvInfo_{};
    bool                     hvHave_  = false;   // hvInfo_ is populated from a live query
    bool                     hvAbiMismatch_ = false; // driver ABI != client ABI (ping() warned)
    std::string              hvStatus_;
    // Cached driver state + elevation: querying the SCM (state) and the process token
    // (isElevated) every frame was wasteful. state refreshes on first use and after a
    // load/unload; elevation never changes within a process, so query it exactly once.
    HvDbgLoader::State       hvState_      = HvDbgLoader::State::Unknown;
    bool                     hvStateValid_ = false;
    int                      hvElevated_   = -1;   // -1 = unknown, else cached isElevated()
};

} // namespace ds
