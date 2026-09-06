// Explicit opt-in: production debugger lifecycle against a test-owned Nubby PID.
#include "Core/BinaryFile.h"
#include "Core/Debugger.h"
#include "Core/GameMakerArchive.h"
#include "Core/GameMakerRunner.h"
#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
using namespace ds;
static const std::string archivePath="C:\\Program Files (x86)\\Steam\\steamapps\\common\\Nubby's Number Factory\\data.win";
static int failures=0;
#define CHECK(x) do{if(!(x)){std::printf("FAIL %d: %s\n",__LINE__,#x);++failures;}}while(0)
static void report(Debugger& d){auto g=d.gameMakerSnapshot();auto n=d.snapshot();std::printf("state=%u native=%u status=%s error=%s event=%s\n",unsigned(g.state),unsigned(n.state),g.status.c_str(),g.error.c_str(),n.lastEvent.c_str());std::fflush(stdout);}
static bool waitFor(Debugger& d,std::function<bool(const GameMakerSessionSnapshot&,const DbgSnapshot&)> done,int ms=30000){
    const auto deadline=GetTickCount64()+ms;
    while(GetTickCount64()<deadline){auto g=d.gameMakerSnapshot();auto n=d.snapshot();
        if(done(g,n))return true;
        if(n.state==DbgState::Terminated)return false;
        if(n.state==DbgState::Paused && !g.stop){
            if(n.exceptionCode && n.exceptionCode!=EXCEPTION_BREAKPOINT && n.exceptionCode!=EXCEPTION_SINGLE_STEP && n.exceptionCode!=kGmlStopExceptionCode){report(d);return false;}
            d.cont();
        }
        Sleep(10);
    }
    report(d);return false;
}
static bool attach(Debugger& d,DWORD pid){std::string error;if(!d.attach(pid,error)){std::printf("attach: %s\n",error.c_str());return false;}
    for(int i=0;i<500 && d.snapshot().modules.empty();++i)Sleep(10);return !d.snapshot().modules.empty();}
static bool connected(Debugger& d,BinaryFile& binary,bool stop){
    std::vector<GmlSavedBreakpoint> bps;
    if(stop){for(const auto& c:binary.gameMakerArchive()->code)if(c.name=="gml_Script___scribble_tick")bps.push_back({{binary.contentHash(),c.index,c.entryOffset,c.parentIndex},true});if(bps.size()!=1)return false;}
    std::string error;
    if(!d.connectGameMaker(binary.gameMakerArchive(),archivePath,binary.contentHash(),bps,error)){std::printf("connect: %s\n",error.c_str());return false;}
    const bool reached=waitFor(d,[=](const auto& g,const auto& n){return g.state==GameMakerSessionState::Failed ||
        (stop ? bool(g.stop)&&n.state==DbgState::Paused:g.state==GameMakerSessionState::Running);});
    report(d);return reached && d.gameMakerSnapshot().ready();
}
static bool disconnect(Debugger& d){const auto before=d.gameMakerSnapshot().revision;d.disconnectGameMaker();const bool done=waitFor(d,[=](const auto& g,const auto&){return g.state==GameMakerSessionState::Disconnected || (g.state==GameMakerSessionState::Failed && g.revision!=before) || g.state==GameMakerSessionState::Inert;});report(d);return done && d.gameMakerSnapshot().state==GameMakerSessionState::Disconnected && !d.gameMakerSnapshot().mappingRetained;}
static bool alive(DWORD pid){HANDLE p=OpenProcess(SYNCHRONIZE,FALSE,pid);const bool result=p && WaitForSingleObject(p,0)==WAIT_TIMEOUT;if(p)CloseHandle(p);return result;}
int main(int argc,char** argv){
    if(argc<3){std::puts("Usage: live_lifecycle_test.exe <explicit owned Nubby PID> <lifecycle|host-loss-running|host-loss-paused|--allow-target-exit>");return 2;}
    const DWORD pid=strtoul(argv[1],nullptr,10);const std::string mode=argv[2];
    BinaryFile binary;if(!binary.load(archivePath) || !binary.gameMakerArchive())return 1;
    if(mode=="--child-running" || mode=="--child-paused"){
        if(argc!=4)return 2;
        HANDLE ready=OpenEventA(EVENT_MODIFY_STATE,FALSE,argv[3]);if(!ready)return 2;
        Debugger d;if(!attach(d,pid) || !connected(d,binary,mode=="--child-paused"))return 1;
        SetEvent(ready);CloseHandle(ready);
        for(;;)Sleep(100); // the parent deliberately terminates this owned host
    }
    if(mode=="host-loss-running" || mode=="host-loss-paused"){
        const std::string eventName="Local\\DsGmlHostLoss-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(GetTickCount64());
        HANDLE ready=CreateEventA(nullptr,TRUE,FALSE,eventName.c_str());if(!ready)return 1;
        char executable[32768]{};if(!GetModuleFileNameA(nullptr,executable,sizeof(executable)))return 1;
        std::string command="\""+std::string(executable)+"\" "+std::to_string(pid)+
            (mode=="host-loss-paused"?" --child-paused ":" --child-running ")+eventName;
        STARTUPINFOA start{};start.cb=sizeof(start);PROCESS_INFORMATION child{};
        if(!CreateProcessA(executable,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&start,&child))return 1;
        HANDLE waits[]={ready,child.hProcess};const DWORD outcome=WaitForMultipleObjects(2,waits,FALSE,30000);
        CHECK(outcome==WAIT_OBJECT_0);
        if(outcome==WAIT_OBJECT_0){Sleep(250);CHECK(TerminateProcess(child.hProcess,77));}
        else TerminateProcess(child.hProcess,78);
        WaitForSingleObject(child.hProcess,5000);CloseHandle(child.hThread);CloseHandle(child.hProcess);CloseHandle(ready);
        Sleep(1000);CHECK(alive(pid));
        HANDLE target=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);ULONG64 before=0,after=0;
        CHECK(target && QueryProcessCycleTime(target,&before));Sleep(2000);CHECK(target && QueryProcessCycleTime(target,&after));CHECK(after>before);
        if(target)CloseHandle(target);CHECK(alive(pid));
        std::printf("HOST LOSS %s target=%u survives, cycles advanced=%llu\n",mode.c_str(),pid,(unsigned long long)(after-before));
    }else{
        Debugger d;if(!attach(d,pid))return 1;std::string error;
        if(mode=="--allow-target-exit"){
            CHECK(connected(d,binary,true));
            HANDLE target=OpenProcess(PROCESS_TERMINATE,FALSE,pid);CHECK(target);
            if(target){CHECK(TerminateProcess(target,0));CloseHandle(target);}
            CHECK(waitFor(d,[](const auto&,const auto& n){return n.state==DbgState::Terminated;}));
            for(int i=0;i<500 && d.gameMakerSnapshot().state!=GameMakerSessionState::Disconnected;++i)Sleep(10);
            CHECK(!d.gameMakerSnapshot().stop);CHECK(!d.gameMakerSnapshot().mappingRetained);report(d);d.detach();
        }else if(mode=="lifecycle"){
            CHECK(d.connectGameMaker(binary.gameMakerArchive(),archivePath+".missing",binary.contentHash(),{},error));
            CHECK(waitFor(d,[](const auto& g,const auto&){return g.state==GameMakerSessionState::Failed;}));
            CHECK(!d.gameMakerSnapshot().helperBase);report(d);
            CHECK(disconnect(d)); // retire failed preparation without native reattach
            CHECK(alive(pid));
            CHECK(d.connectGameMaker(binary.gameMakerArchive(),archivePath,binary.contentHash(),{},error));
            CHECK(disconnect(d)); // cancellation while async preparation is pending
            CHECK(connected(d,binary,false));CHECK(disconnect(d));
            CHECK(connected(d,binary,true));CHECK(disconnect(d));
            CHECK(connected(d,binary,false));CHECK(d.gameMakerCommand(GmlControlCommand::Pause,{},error));CHECK(disconnect(d));
            d.detach();CHECK(alive(pid));
        }else return 2;
    }
    std::printf("live_lifecycle_test: %s (%d failures)\n",failures?"FAILED":"PASSED",failures);return failures?1:0;
}
