#pragma once
#include "ITab.h"
#include "ConnectionsTab.h"
#include "../Core/JdwpClient.h"
#include "../Core/JvmAttach.h"
#include "../Core/JvmClass.h"
#include "../Core/ProcessManager.h"
#include "../Disasm/IDisassembler.h"
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace ds {

// Communications tab: native-process side. Real Win32 process enumeration and
// attach (debug API), module listing for the selected process, the
// connections/channels model used to talk to external agents/drivers, and the
// Java debug (JDWP) console for bytecode-level JVM debugging.
class CommunicationsTab final : public ITab {
public:
    CommunicationsTab();
    ~CommunicationsTab() override;

    const char* name() const override { return "Communications"; }
    void render(AppContext& ctx) override;

private:
    void refreshProcesses();
    void renderProcesses(AppContext& ctx);
    void renderModules();
    void renderConnections(AppContext& ctx);
    void renderJdwp(AppContext& ctx);         // Java debug (JDWP) console
    void renderGameMaker(AppContext& ctx);
    void loadJdwpMethod(AppContext& ctx, uint64_t classID, uint64_t methodID,
                        const std::string& label);

    struct Conn {
        std::string local;
        std::string remote;
        std::string protocol; // TCP / UDP
        std::string family;   // IPv4 / IPv6
        std::string state;
        bool        ipv6 = false;
    };

    struct ConnJob { uint64_t epoch = 0; uint32_t pid = 0; };
    struct ConnResult {
        uint64_t epoch = 0;
        uint32_t pid = 0;
        std::vector<Conn> connections;
        std::string status;
    };
    static ConnResult collectConnections(const ConnJob& job);
    void requestConnectionRefresh(uint32_t pid);
    void pumpConnectionRefresh();
    void connectionWorkerLoop(std::stop_token stop);

    ProcessManager           pm_;
    std::vector<ProcessInfo> procs_;
    std::vector<ModuleInfo>  mods_;
    bool                     enumerated_ = false;
    int                      selProc_    = -1;
    uint32_t                 modsForPid_ = 0;
    std::string              status_;

    std::vector<Conn>        conns_;          // live per-process connections
    uint32_t                 connsForPid_ = 0;
    uint32_t                 connsRequestedPid_ = 0;
    std::string              connStatus_;     // empty on a complete 4-table refresh
    double                   connNextRefresh_ = 0.0;
    bool                     connAutoRefresh_ = true;
    bool                     connShowV4_ = true;
    bool                     connShowV6_ = true;
    bool                     connShowTcp_ = true;
    bool                     connShowUdp_ = true;
    char                     connFilter_[96] = "";
    char filter_[64] = "";

    // Communications is the single home for process attach, system-wide network
    // activity, and JVM/JDWP work.  Keeping these as internal workspaces matches
    // the fixed nine-section shell and avoids spending permanent top-level
    // navigation on a second communications surface.
    int                      workspaceView_ = 0; // 0 native, 1 network, 2 Java/JDWP, 3 GameMaker
    std::string              gmlStatus_;
    ConnectionsTab           systemConnections_;

    // IP Helper table enumeration can allocate/touch tens of MiB and is never
    // allowed to execute from render(). The worker owns each query/result;
    // epochs reject a response for a process the user has already left.
    std::mutex               connWorkerMutex_;
    std::condition_variable  connWorkerCv_;
    std::optional<ConnJob>   pendingConnJob_;
    std::optional<ConnResult> readyConnResult_;
    std::atomic<uint64_t>    desiredConnEpoch_{0};
    std::atomic<bool>        connRefreshRunning_{false};
    std::jthread             connWorker_;

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
    char        jdwpProcessFilter_[96] = "";
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
