#pragma once
#include "ITab.h"
#include "../Core/JdwpClient.h"
#include "../Core/JvmAttach.h"
#include "../Core/JvmClass.h"
#include "../Core/ProcessManager.h"
#include "../Disasm/IDisassembler.h"
#include "../Hv/HvDbgClient.h"
#include "../Hv/HvDbgLoader.h"
#include "../Hv/HvDbgProtocol.h"
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ds {

// Communications tab: native-process side. Real Win32 process enumeration and
// attach (debug API), module listing for the selected process, the
// connections/channels model used to talk to external agents/drivers, and the
// Java debug (JDWP) console for bytecode-level JVM debugging.
class CommunicationsTab final : public ITab {
public:
    const char* name() const override { return "Communications"; }
    void render(AppContext& ctx) override;

private:
    void renderProcesses(AppContext& ctx);
    void renderModules();
    void renderConnections();
    void renderHvDbg();                       // AMD-V (SVM) hypervisor channel: \\.\HvDbg
    void renderJdwp(AppContext& ctx);         // Java debug (JDWP) console
    void loadJdwpMethod(AppContext& ctx, uint64_t classID, uint64_t methodID,
                        const std::string& label);
    void refreshConnections(uint32_t pid);   // live per-process TCP/UDP endpoints

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

    // ---- Java debug (JDWP) console state ----
    char        jdwpHost_[64]        = "127.0.0.1";
    int         jdwpPort_            = 5005;
    std::string jdwpStatus_;                       // last attach/RPC error, empty = fine
    // dynamic-attach (inject) path: VM flavor/bitness of the selected process, cached by pid
    uint32_t    jdwpInjectPid_  = 0;
    JvmInfo     jdwpInjectInfo_;                    // flavor None until a JVM process is selected
    double      jdwpInjectNextPoll_ = 0.0;          // re-InspectJvm() deadline while no VM seen yet
                                                    // (an EXE launcher loads jvm.dll after startup)
    bool        jdwpSuspendOnAttach_ = true;        // freeze all VM threads right after connecting
                                                    // (so an EXE-launcher's Java main logic can be
                                                    // breakpointed before it runs on)
    char        jdwpClassFilter_[64] = "";
    uint64_t    jdwpSelClass_  = 0;                // selected class typeID
    std::string jdwpSelClassName_;
    std::vector<JdwpMethodRow> jdwpMethods_;       // methods of the selected class
    std::vector<Instruction>   jdwpInsns_;         // disassembled live bytecode (VA == bci)
    uint64_t    jdwpInsnsClass_ = 0, jdwpInsnsMethod_ = 0;   // what jdwpInsns_ shows
    std::string jdwpInsnsLabel_;                   // "Bar.main" header for the listing
    std::shared_ptr<JvmClassFile> jdwpCp_;         // per-class constant pool (symbolication)
    uint64_t    jdwpCpClass_ = 0;
    // last stop already reacted to (auto-follow + scroll happen once per stop)
    uint64_t    jdwpSeenStopClass_ = 0, jdwpSeenStopMethod_ = 0, jdwpSeenStopBci_ = ~0ull;
    bool        jdwpScrollToStop_ = false;
    // class-filter result cache (rebuilt when the list or the filter changes)
    std::shared_ptr<const std::vector<JdwpClassRow>> jdwpClassesRef_;
    std::string jdwpFilterCache_ = "\x01";         // never matches a real filter initially
    std::vector<int> jdwpFiltered_;                // indices into *jdwpClassesRef_
};

} // namespace ds
