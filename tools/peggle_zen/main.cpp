// Standalone AOB-backed console for one next-shot Zen charge in Peggle Deluxe 1.01.
// No DLL, injected code, permanent patch, hotkey, or remote function call.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include "Core/ProcessMemorySession.h"
#include "zen_core.h"
#include <array>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <utility>

namespace {
std::atomic_bool pauseActive=false;
std::atomic_bool shutdownRequested=false;
BOOL WINAPI consoleControl(DWORD event) {
    (void)event;
    shutdownRequested.store(true);
    if (!pauseActive.load()) return FALSE;
    // Let the RAII guard balance its suspends before normal console shutdown.
    while (pauseActive.load()) Sleep(10);
    return FALSE;
}
struct Handle {
    HANDLE value=nullptr;
    explicit Handle(HANDLE h=nullptr) : value(h) {}
    ~Handle() { if (*this) CloseHandle(value); }
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
    Handle(Handle&& other) noexcept : value(std::exchange(other.value,nullptr)) {}
    explicit operator bool() const { return value && value!=INVALID_HANDLE_VALUE; }
};
std::runtime_error windowsError(const char* operation) {
    return std::runtime_error(std::string(operation)+" (Windows error "+std::to_string(GetLastError())+").");
}
std::vector<DWORD> gameProcesses() {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    if (!snapshot) throw windowsError("Cannot list processes");
    PROCESSENTRY32W item{}; item.dwSize=sizeof(item);
    if (!Process32FirstW(snapshot.value,&item)) throw windowsError("Cannot read process list");
    std::vector<DWORD> result;
    do { if (!_wcsicmp(item.szExeFile,L"popcapgame1.exe")) result.push_back(item.th32ProcessID); }
    while (Process32NextW(snapshot.value,&item));
    if (GetLastError()!=ERROR_NO_MORE_FILES) throw windowsError("Incomplete process list");
    return result;
}
struct Module { uint32_t base=0,size=0; };
Module mainModule(DWORD pid) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid));
    if (!snapshot) throw windowsError("Cannot list game modules");
    MODULEENTRY32W item{}; item.dwSize=sizeof(item);
    if (!Module32FirstW(snapshot.value,&item)) throw windowsError("Cannot read game modules");
    Module result;
    do {
        if (_wcsicmp(item.szModule,L"popcapgame1.exe")) continue;
        const uint64_t base=reinterpret_cast<uintptr_t>(item.modBaseAddr);
        if (result.size && result.base==base && result.size==item.modBaseSize) continue;
        if (result.size || base<0x10000 || item.modBaseSize<4096 || item.modBaseSize>64u*1024u*1024u ||
            base+item.modBaseSize>0x100000000ull)
            throw std::runtime_error("Unsupported or ambiguous game module (base "+std::to_string(base)+
                ", size "+std::to_string(item.modBaseSize)+", previous base "+std::to_string(result.base)+
                ", previous size "+std::to_string(result.size)+").");
        result={static_cast<uint32_t>(base),item.modBaseSize};
    } while (Module32NextW(snapshot.value,&item));
    if (GetLastError()!=ERROR_NO_MORE_FILES) throw windowsError("Incomplete module list");
    if (!result.size) throw std::runtime_error("The actual game module is not ready. Try again.");
    return result;
}
std::vector<DWORD> threadIds(DWORD pid) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0));
    if (!snapshot) throw windowsError("Cannot list game threads");
    THREADENTRY32 item{}; item.dwSize=sizeof(item);
    if (!Thread32First(snapshot.value,&item)) throw windowsError("Cannot read game threads");
    std::vector<DWORD> result;
    do { if (item.th32OwnerProcessID==pid) result.push_back(item.th32ThreadID); }
    while (Thread32Next(snapshot.value,&item));
    if (GetLastError()!=ERROR_NO_MORE_FILES) throw windowsError("Incomplete thread list");
    if (result.empty() || result.size()>256) throw std::runtime_error("Unexpected game thread count.");
    std::sort(result.begin(),result.end());
    return result;
}
class BriefPause {
    struct Thread { Handle handle; bool held=false; };
    std::vector<Thread> threads_;
public:
    BriefPause() {
        pauseActive.store(true);
        if (shutdownRequested.load()) {
            pauseActive.store(false);
            throw std::runtime_error("Console shutdown requested; no edit started.");
        }
    }
    ~BriefPause() {
        if (!resume()) {
            // Retain the handles and recover our suspend before letting the tool exit.
            std::cerr<<"Thread resume failed; retrying. Keep this console open.\n";
            while (!resume()) Sleep(50);
        }
        pauseActive.store(false);
    }
    void begin(DWORD pid,const std::function<void()>& validateOwner) {
        validateOwner();
        const ULONGLONG started=GetTickCount64();
        const auto before=threadIds(pid);
        threads_.reserve(before.size());
        for (DWORD tid:before) {
            validateOwner();
            Handle thread(OpenThread(THREAD_SUSPEND_RESUME|THREAD_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,tid));
            if (!thread || GetProcessIdOfThread(thread.value)!=pid) throw windowsError("A game thread changed or could not be opened");
            threads_.push_back({std::move(thread),false});
            if (SuspendThread(threads_.back().handle.value)==DWORD(-1)) throw windowsError("Cannot briefly pause game thread");
            threads_.back().held=true;
            if (GetTickCount64()-started>500) throw std::runtime_error("Pausing took too long; no edit started.");
        }
        if (threadIds(pid)!=before) throw std::runtime_error("Game threads changed during the pause; retry.");
        validateOwner();
    }
    bool resume() {
        bool ok=true;
        for (size_t i=threads_.size();i-->0;) {
            auto& thread=threads_[i];
            if (!thread.held) continue;
            if (WaitForSingleObject(thread.handle.value,0)==WAIT_OBJECT_0 ||
                ResumeThread(thread.handle.value)!=DWORD(-1)) thread.held=false;
            else ok=false;
        }
        return ok;
    }
};

class Game {
    ds::ProcessMemorySession memory_;
    ds::ProcessMemoryIdentity identity_;
    Module module_;
    zen::Layout layout_;
    std::vector<zen::Range> code_;
    std::array<std::vector<uint8_t>,3> signatureBytes_;
    bool read(uint32_t address,void* output,size_t size) {
        return memory_.read(identity_,address,output,size)==size;
    }
    zen::Reader reader() { return [this](uint32_t address,void* out,size_t size) { return read(address,out,size); }; }
    void validateSession() {
        const auto current=memory_.snapshot();
        if (!current.alive || !ds::ProcessMemoryIdentityMatches(current.identity,identity_))
            throw std::runtime_error("The exact game process has exited or changed. Rescan.");
    }
    std::array<uint32_t,3> sites() const { return {layout_.boardSite,layout_.layoutSite,layout_.zenSite}; }
public:
    void connect(DWORD requestedPid,bool write) {
        DWORD pid=requestedPid;
        if (!pid) {
            const auto choices=gameProcesses();
            if (choices.empty()) throw std::runtime_error("Peggle is not running. Open the game and a level first.");
            if (choices.size()!=1) throw std::runtime_error("Multiple games are running. Use --pid <number> to choose one.");
            pid=choices.front();
        }
        std::string error;
        if (!memory_.open(pid,{write,false},&error)) throw std::runtime_error(error);
        const auto snapshot=memory_.snapshot();
        if (snapshot.name!="popcapgame1.exe" || !snapshot.bitnessKnown || !snapshot.is32)
            throw std::runtime_error("Select the 32-bit popcapgame1.exe game, not its Peggle.exe launcher.");
        identity_=snapshot.identity;
        module_=mainModule(pid);
        const auto map=memory_.committedRegions(identity_);
        if (!map.complete) throw std::runtime_error("Could not obtain a complete memory map: "+map.error);
        const uint64_t moduleEnd=static_cast<uint64_t>(module_.base)+module_.size;
        for (const auto& region:map.regions) {
            if (!region.readable || !region.executable || region.guarded || region.noAccess) continue;
            const uint64_t start=std::max<uint64_t>(region.base,module_.base);
            const uint64_t end=std::min<uint64_t>(region.base+region.size,moduleEnd);
            if (start>=end) continue;
            zen::Range range{static_cast<uint32_t>(start),std::vector<uint8_t>(static_cast<size_t>(end-start))};
            for (size_t offset=0;offset<range.bytes.size();offset+=65536) {
                const size_t size=std::min<size_t>(65536,range.bytes.size()-offset);
                if (!read(static_cast<uint32_t>(start+offset),range.bytes.data()+offset,size))
                    throw std::runtime_error("Incomplete executable-memory read. No AOB result is trusted.");
            }
            if (!code_.empty() && static_cast<uint64_t>(code_.back().address)+code_.back().bytes.size()==start)
                code_.back().bytes.insert(code_.back().bytes.end(),range.bytes.begin(),range.bytes.end());
            else code_.push_back(std::move(range));
        }
        layout_=zen::resolve(code_);
        if (layout_.appGlobal<module_.base || static_cast<uint64_t>(layout_.appGlobal)+4>moduleEnd)
            throw std::runtime_error("The AOB's global pointer slot is outside the game module.");
        const auto addresses=sites();
        const std::array<const char*,3> patterns{zen::kBoardAob,zen::kLayoutAob,zen::kZenAob};
        for (size_t i=0;i<addresses.size();++i) {
            auto& bytes=signatureBytes_[i]; bytes.resize(zen::Pattern(patterns[i]).bytes.size());
            if (!read(addresses[i],bytes.data(),bytes.size())) throw std::runtime_error("AOB bytes changed during scan.");
            // Check the live bytes again, including the fixed parts of each signature.
            if (zen::unique({zen::Range{addresses[i],bytes}},zen::Pattern(patterns[i]),"Recheck")!=addresses[i])
                throw std::runtime_error("AOB changed during scan.");
        }
        // Do not retain decoded operands from an earlier version of any signature.
        std::vector<zen::Range> finalSignatures;
        for (size_t i=0;i<addresses.size();++i) finalSignatures.push_back({addresses[i],signatureBytes_[i]});
        const auto finalLayout=zen::resolve(finalSignatures);
        if (finalLayout.appGlobal!=layout_.appGlobal) throw std::runtime_error("AOB operands changed during scan.");
        validateSession();
    }
    zen::State status() { validateSession(); return zen::inspect(reader(),layout_,module_.base); }
    zen::Grant grant() {
        validateSession();
        BriefPause pause;
        pause.begin(identity_.pid,[this] { validateSession(); });
        validateSession();
        const auto addresses=sites();
        for (size_t i=0;i<addresses.size();++i) {
            std::vector<uint8_t> now(signatureBytes_[i].size());
            if (!read(addresses[i],now.data(),now.size()) || now!=signatureBytes_[i])
                throw std::runtime_error("Code changed since the AOB scan; no write made.");
        }
        const auto state=status();
        const auto plan=zen::planGrant(state);
        zen::validateLoadedBall(reader(),state,module_.base);
        if (static_cast<int32_t>(zen::read32(reader(),plan.address))!=plan.before)
            throw std::runtime_error("The charge changed before the write; retry.");
        const auto result=memory_.write(identity_,plan.address,&plan.after,sizeof(plan.after),{});
        if (!result.ok()) throw std::runtime_error("Grant failed: "+result.error);
        if (!pause.resume()) throw std::runtime_error("Charge was written, but a game thread needs resume recovery.");
        return plan;
    }
    void print(const zen::State& state) const {
        std::cout<<"PID "<<identity_.pid<<" | AOB matches: 1 / 1 / 1\n"
                 <<"Player "<<(state.player+1)<<" | Zen charges: "<<state.charges<<" | Game state: "<<state.phase<<"\n"
                 <<"Counter: 0x"<<std::hex<<std::uppercase<<state.countAddress<<std::dec<<"\n";
    }
};

template<class T> T fileValue(const std::vector<uint8_t>& bytes,size_t offset) {
    if (offset>bytes.size() || bytes.size()-offset<sizeof(T)) throw std::runtime_error("Truncated PE file.");
    T value{}; std::memcpy(&value,bytes.data()+offset,sizeof(value)); return value;
}
void verifyFile(const std::filesystem::path& path) {
    std::ifstream file(path,std::ios::binary|std::ios::ate);
    if (!file) throw std::runtime_error("Cannot open analysis EXE.");
    const auto length=file.tellg();
    if (length<64 || length>64*1024*1024) throw std::runtime_error("Unsupported PE file size.");
    std::vector<uint8_t> bytes(static_cast<size_t>(length)); file.seekg(0);
    if (!file.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size())))
        throw std::runtime_error("Incomplete file read.");
    const size_t pe=fileValue<uint32_t>(bytes,0x3c);
    if (fileValue<uint16_t>(bytes,0)!=0x5a4d || fileValue<uint32_t>(bytes,pe)!=0x4550 ||
        fileValue<uint16_t>(bytes,pe+4)!=0x14c || fileValue<uint16_t>(bytes,pe+24)!=0x10b)
        throw std::runtime_error("Expected a PE32 x86 executable.");
    const auto count=fileValue<uint16_t>(bytes,pe+6);
    const size_t sections=pe+24+fileValue<uint16_t>(bytes,pe+20);
    const uint32_t base=fileValue<uint32_t>(bytes,pe+24+28);
    if (!count || count>96) throw std::runtime_error("Invalid PE section count.");
    std::vector<zen::Range> ranges;
    for (unsigned i=0;i<count;++i) {
        const size_t section=sections+i*40;
        const auto flags=fileValue<uint32_t>(bytes,section+36);
        if (!(flags&IMAGE_SCN_MEM_EXECUTE)) continue;
        const auto rva=fileValue<uint32_t>(bytes,section+12);
        const auto size=fileValue<uint32_t>(bytes,section+16);
        const auto raw=fileValue<uint32_t>(bytes,section+20);
        if (raw>bytes.size() || size>bytes.size()-raw || static_cast<uint64_t>(base)+rva+size>UINT32_MAX)
            throw std::runtime_error("Invalid executable section.");
        ranges.push_back({base+rva,std::vector<uint8_t>(bytes.begin()+raw,bytes.begin()+raw+size)});
    }
    const auto layout=zen::resolve(ranges);
    std::cout<<"Read-only file verification: all 3 AOBs have exactly one match.\n"<<std::hex<<std::uppercase
             <<"Board getter: 0x"<<layout.boardSite<<" | Layout: 0x"<<layout.layoutSite<<" | Zen consumer: 0x"<<layout.zenSite
             <<"\nApp global slot: 0x"<<layout.appGlobal<<" | Board +0x"<<layout.boardOffset<<" | Logic +0x"<<layout.logicOffset
             <<"\nCurrent player +0x"<<layout.playerOffset<<" | Zen charges +0x"<<layout.countOffset<<std::dec<<"\n";
}
int perform(DWORD pid,bool grant) {
    try {
        Game game; game.connect(pid,grant);
        if (grant) {
            const auto result=game.grant();
            std::cout<<"Added one Zen charge: "<<result.before<<" -> "<<result.after<<". Return to Peggle and fire.\n";
        } else game.print(game.status());
        return 0;
    } catch (const std::exception& error) {
        std::cerr<<error.what()<<"\n"; return 1;
    }
}
} // namespace
int wmain(int argc,wchar_t** argv) {
    try {
        if (!SetConsoleCtrlHandler(consoleControl,TRUE)) throw windowsError("Cannot install console-close recovery");
        DWORD pid=0; std::wstring action;
        for (int i=1;i<argc;++i) {
            const std::wstring argument=argv[i];
            if (argument==L"--pid" && i+1<argc) {
                const std::wstring value=argv[++i]; size_t consumed=0;
                const auto parsed=std::stoull(value,&consumed,10);
                if (consumed!=value.size() || !parsed || parsed>MAXDWORD) throw std::runtime_error("Invalid PID.");
                pid=static_cast<DWORD>(parsed);
            } else if (argument==L"--verify-file" && i+1<argc) {
                if (i+2!=argc || !action.empty() || pid) throw std::runtime_error("Use --verify-file <path> on its own.");
                verifyFile(argv[++i]); return 0;
            } else if ((argument==L"--check" || argument==L"--grant") && action.empty()) action=argument;
            else if (argument==L"--help") {
                std::cout<<"PeggleZen.exe [--pid PID] [--check | --grant]\nPeggleZen.exe --verify-file <analysis.exe>\nWithout an action, opens the console menu.\n"; return 0;
            } else throw std::runtime_error("Unknown argument. Use --help.");
        }
        if (!action.empty()) return perform(pid,action==L"--grant");
        SetConsoleTitleW(L"Peggle - One Zen Shot");
        std::cout<<"PEGGLE - ONE ZEN SHOT\nOpen a level and leave a ball ready to fire.\n";
        for (std::string choice;;) {
            std::cout<<"\n[1] Give one Zen shot\n[2] Check game / rescan\n[0] Exit\n> "<<std::flush;
            if (!std::getline(std::cin,choice) || choice=="0") break;
            if (choice=="1") perform(pid,true);
            else if (choice=="2") perform(pid,false);
            else std::cout<<"Enter 1, 2, or 0.\n";
        }
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<"\n"; return 1; }
}
