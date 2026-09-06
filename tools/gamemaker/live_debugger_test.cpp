// Explicit opt-in acceptance harness against the actual installed Nubby build.
// Uses the production Debugger and embedded helper; no parallel debug authority.
#include "Core/BinaryFile.h"
#include "Core/Debugger.h"
#include "Core/GameMakerArchive.h"
#include "Core/GameMakerHelperImage.h"
#include "Core/GameMakerRunner.h"
#include "Core/Project.h"
#include <windows.h>
#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

using namespace ds;
static int failures=0;
#define CHECK(x) do { if(!(x)){std::printf("FAIL line %d: %s\n",__LINE__,#x);++failures;} }while(0)
static void benchmark(DWORD pid,const char* mode,Debugger* debugger=nullptr) {
    HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!process){CHECK(process);return;}
    const auto ticks=[](FILETIME value){return (uint64_t(value.dwHighDateTime)<<32)|value.dwLowDateTime;};
    for(int sample=0;sample<3;++sample) {
        FILETIME created{},exit{},kernel0{},user0{},kernel1{},user1{};ULONG64 cycles0=0,cycles1=0;
        const auto started=GetTickCount64();GetProcessTimes(process,&created,&exit,&kernel0,&user0);QueryProcessCycleTime(process,&cycles0);
        while(GetTickCount64()-started<1000) {
            if(debugger && debugger->snapshot().state==DbgState::Paused) {
                std::printf("BENCH invalid: target paused in %s\n",mode);CHECK(false);CloseHandle(process);return;
            }
            Sleep(10);
        }
        GetProcessTimes(process,&created,&exit,&kernel1,&user1);QueryProcessCycleTime(process,&cycles1);
        std::printf("BENCH mode=%s sample=%d wall_ms=%llu cpu_ms=%.3f cycles=%llu\n",mode,sample,
            (unsigned long long)(GetTickCount64()-started),double(ticks(kernel1)+ticks(user1)-ticks(kernel0)-ticks(user0))/10000.,
            (unsigned long long)(cycles1-cycles0));std::fflush(stdout);
    }
    CloseHandle(process);
}
static void status(Debugger& debugger) {
    auto s=debugger.gameMakerSnapshot();auto n=debugger.snapshot();
    std::printf("GML state=%u revision=%llu bound=%u native=%u event=%s status=%s error=%s\n",
        unsigned(s.state),(unsigned long long)s.revision,s.boundBreakpoints,unsigned(n.state),
        n.lastEvent.c_str(),s.status.c_str(),s.error.c_str());std::fflush(stdout);
}
static GameMakerSessionSnapshot waitStop(Debugger& debugger,uint64_t after=0,int timeout=30000) {
    const auto until=GetTickCount64()+timeout;uint64_t revision=UINT64_MAX;
    while(GetTickCount64()<until) {
        auto s=debugger.gameMakerSnapshot();auto n=debugger.snapshot();
        if(s.revision!=revision){revision=s.revision;status(debugger);}
        if(s.stop && s.stop->identity.stopSequence>after && n.state==DbgState::Paused)return s;
        if(s.state==GameMakerSessionState::Failed || n.state==DbgState::Terminated)return s;
        if(n.state==DbgState::Paused && !s.stop) {
            if(n.exceptionCode && n.exceptionCode!=EXCEPTION_BREAKPOINT && n.exceptionCode!=EXCEPTION_SINGLE_STEP){status(debugger);return s;}
            debugger.cont();
        }
        Sleep(10);
    }
    status(debugger);return debugger.gameMakerSnapshot();
}
static bool doStep(Debugger& debugger,GameMakerSessionSnapshot& stop,GmlControlCommand command) {
    const auto sequence=stop.stop->identity.stopSequence;
    std::string error;
    if(!debugger.gameMakerCommand(command,stop.stop->identity,error)) {
        std::printf("Command rejected: %s\n",error.c_str());return false;
    }
    auto next=waitStop(debugger,sequence);
    if(!next.stop || next.stop->identity.stopSequence<=sequence)return false;
    stop=std::move(next);
    const auto& code=stop.archive->code[stop.stop->location.codeIndex];
    std::printf("STOP %s +0x%x frame=%llu depth=%u vars=%u reason=%u\n",code.name.c_str(),
        stop.stop->location.byteOffset,(unsigned long long)stop.stop->frames[0].frameId,
        stop.stop->frames[0].depth,stop.stop->numericSlotCount,unsigned(stop.stop->reason));
    return stop.stop->reason!=GmlStopReason::Error;
}
static std::string numericText(const GmlHelperNumericSlot& slot) {
    char text[128]{};
    if(slot.kind==GmlNumericKind::Real || slot.kind==GmlNumericKind::Boolean)
        std::snprintf(text,sizeof(text),"%.17g",std::bit_cast<double>(slot.value.payload));
    else if(slot.kind==GmlNumericKind::Int32)std::snprintf(text,sizeof(text),"%d",(int32_t)slot.value.payload);
    else std::snprintf(text,sizeof(text),"%lld",(long long)(int64_t)slot.value.payload);
    return text;
}
static bool editAndWait(Debugger& debugger,const GmlPauseIdentity& owner,uint32_t index,
                        const std::string& text,GmlRValue* result=nullptr) {
    const auto revision=debugger.gameMakerSnapshot().revision;
    std::string error;
    if(!debugger.editGameMakerNumeric(owner,revision,index,text,error)){std::printf("EDIT rejected: %s\n",error.c_str());return false;}
    for(int i=0;i<500;++i){
        auto state=debugger.gameMakerSnapshot();
        if(state.revision>revision){
            std::printf("EDIT %s\n",state.lastEdit.c_str());
            if(result && state.stop)*result=state.stop->numericSlots[index].value;
            return state.lastEdit.find("written and verified")!=std::string::npos;
        }
        Sleep(10);
    }
    return false;
}
int main(int argc,char** argv) {
    if(argc<2){std::puts("Usage: live_debugger_test.exe <explicit Nubby PID> [script-name]");return 2;}
    const auto pid=(DWORD)std::strtoul(argv[1],nullptr,10);
    const std::string script=argc>2?argv[2]:"gml_Script___scribble_tick";
    const std::string path="C:\\Program Files (x86)\\Steam\\steamapps\\common\\Nubby's Number Factory\\data.win";
    BinaryFile binary;
    if(!binary.load(path)){std::puts("Could not load Nubby archive.");return 1;}
    const auto archive=binary.gameMakerArchive();
    if(!archive){std::puts("No GameMaker metadata.");return 1;}
    const auto code=std::find_if(archive->code.begin(),archive->code.end(),[&](const auto& c){return c.name==script;});
    if(code==archive->code.end()){std::printf("Missing script: %s\n",script.c_str());return 1;}
    std::printf("Archive %llu CODE=%u script=%s +0x%x\n",(unsigned long long)binary.contentHash(),code->index,code->name.c_str(),code->entryOffset);
    std::vector<GmlSavedBreakpoint> breakpoints={{{binary.contentHash(),code->index,code->entryOffset,code->parentIndex},true}};
    // A single intent file is reused unchanged by every restart acceptance run.
    // It is isolated from the user's actual project sidecars and game saves.
    const std::filesystem::path intentPath="build/gamemaker-live-test/restart-intent.json";
    ProjectState intent;
    if(std::filesystem::exists(intentPath)) {
        std::ifstream in(intentPath);const std::string text((std::istreambuf_iterator<char>(in)),{});
        if(!DeserializeProject(text,intent) || intent.hash!=binary.contentHash() || intent.gmlBreakpoints.empty())return 1;
        breakpoints=intent.gmlBreakpoints;
        if(breakpoints[0].location.codeIndex!=code->index)return 1;
    } else {
        intent.hash=binary.contentHash();intent.gmlBreakpoints=breakpoints;
        GmlSavedWatch watch;watch.target.archiveHash=intent.hash;watch.target.variableName="ItemSfx";
        watch.label="Restart acceptance numeric global";intent.gmlWatches.push_back(watch);
        std::ofstream out(intentPath);out<<SerializeProject(intent);if(!out)return 1;
    }
    Debugger debugger;std::string error;
    benchmark(pid,"baseline");
    if(!debugger.attach(pid,error)){std::printf("Attach failed: %s\n",error.c_str());return 1;}
    // CREATE_PROCESS/LOAD_DLL evidence is populated asynchronously after attach.
    for(int i=0;i<500 && debugger.snapshot().modules.empty();++i)Sleep(10);
    for(int i=0;i<100;++i){if(debugger.snapshot().state==DbgState::Paused)debugger.cont();Sleep(10);}
    benchmark(pid,"native-attached-idle",&debugger);
    if(!debugger.connectGameMaker(archive,path,binary.contentHash(),breakpoints,error)) {
        std::printf("GML connect failed: %s\n",error.c_str());debugger.detach();return 1;
    }
    auto stop=waitStop(debugger,0,45000);
    if(!stop.stop){std::puts("No validated GML stop.");debugger.detach();return 1;}
    CHECK(stop.stop->location.codeIndex==code->index);
    CHECK(stop.stop->location.byteOffset==code->entryOffset);
    CHECK(stop.instructionStopsVerified);
    CHECK(stop.boundBreakpoints==1);
    std::vector<GmlVariableCandidate> watchCandidates;
    for(uint32_t i=0;i<stop.stop->numericSlotCount;++i){const auto& slot=stop.stop->numericSlots[i];
        watchCandidates.push_back({slot.scope,slot.objectIndex,{slot.name,slot.nameLength},slot.instanceId,slot.frameId,i});}
    const auto watch=ResolveGmlVariableTarget(intent.gmlWatches[0].target,intent.hash,stop.stop->identity,watchCandidates,stop.stop->globalsComplete!=0);
    std::printf("WATCH status=%u globalsComplete=%u numeric=%u\n",unsigned(watch.status),stop.stop->globalsComplete,stop.stop->numericSlotCount);
    CHECK(watch.resolved());
    if(watch.resolved())std::printf("REBIND pid=%u CODE=%u offset=%x watch=%s address=%llx value=%s\n",pid,
        stop.stop->location.codeIndex,stop.stop->location.byteOffset,intent.gmlWatches[0].target.variableName.c_str(),
        (unsigned long long)stop.stop->numericSlots[watch.slotIndex].address,numericText(stop.stop->numericSlots[watch.slotIndex]).c_str());
    std::printf("REGISTRY instances=%u complete=%u\n",stop.stop->instanceCount,stop.stop->instancesComplete);
    // Native register APIs cannot mutate the helper's saved continuation.
    auto native=debugger.snapshot();
    CHECK(!debugger.setRegisters(native.regs));
    CHECK(!debugger.setRegister("rax",native.regs.rax));
    const auto originalStop=stop.stop->identity;
    for(int i=0;i<6 && stop.stop;++i)CHECK(doStep(debugger,stop,GmlControlCommand::StepInto));
    uint32_t numeric=UINT32_MAX;
    for(uint32_t i=0;i<stop.stop->numericSlotCount;++i){
        const auto& slot=stop.stop->numericSlots[i];
        if(slot.writable && slot.kind==GmlNumericKind::Real && std::isfinite(std::bit_cast<double>(slot.value.payload))){numeric=i;break;}
    }
    CHECK(numeric!=UINT32_MAX);
    if(numeric!=UINT32_MAX){
        const auto slot=stop.stop->numericSlots[numeric];
        std::printf("NUMERIC %.*s address=%llx original=%s\n",slot.nameLength,slot.name,(unsigned long long)slot.address,numericText(slot).c_str());
        GmlRValue changed{},restored{};
        CHECK(editAndWait(debugger,stop.stop->identity,numeric,"123.25",&changed));
        CHECK(changed.payload==std::bit_cast<uint64_t>(123.25));
        CHECK(changed.flags==slot.value.flags && changed.typeTag==slot.value.typeTag);
        // Restore before executing another GML instruction: no game/save effects.
        CHECK(editAndWait(debugger,stop.stop->identity,numeric,numericText(slot),&restored));
        CHECK(restored==slot.value);
        CHECK(!debugger.editGameMakerNumeric(originalStop,debugger.gameMakerSnapshot().revision,numeric,"0",error));
    }
    CHECK(doStep(debugger,stop,GmlControlCommand::StepOver));
    if(stop.stop && stop.stop->frames[0].parentFrameId)CHECK(doStep(debugger,stop,GmlControlCommand::StepOut));
    // Inspect an exact allocation token while the native event owns the pause.
    bool instanceEdited=false;
    for(uint32_t instanceIndex=0;instanceIndex<stop.stop->instanceCount && !instanceEdited;++instanceIndex) {
        const auto instance=stop.stop->instances[instanceIndex];
        if(!instance.instanceId)continue;
        const auto before=debugger.gameMakerSnapshot();
        if(!debugger.inspectGameMakerInstance(before.stop->identity,kGmlNoCodeIndex,instance.instanceId,error))continue;
        for(int i=0;i<500 && debugger.gameMakerSnapshot().revision==before.revision;++i)Sleep(10);
        stop=debugger.gameMakerSnapshot();
        if(!stop.stop)break;
        for(uint32_t index=0;index<stop.stop->numericSlotCount;++index) {
            const auto slot=stop.stop->numericSlots[index];
            if(slot.scope!=GmlVariableScope::SessionInstance || slot.instanceId!=instance.instanceId || !slot.writable ||
               slot.kind!=GmlNumericKind::Real || !std::isfinite(std::bit_cast<double>(slot.value.payload)))continue;
            std::printf("INSTANCE EDIT token=%llu raw=%u object=%u variable=%.*s address=%llx value=%s\n",
                (unsigned long long)instance.instanceId,instance.runtimeInstanceNumber,instance.objectIndex,
                slot.nameLength,slot.name,(unsigned long long)slot.address,numericText(slot).c_str());
            GmlRValue changed{},restored{};
            CHECK(editAndWait(debugger,stop.stop->identity,index,"123.25",&changed));
            CHECK(changed.payload==std::bit_cast<uint64_t>(123.25) && changed.typeTag==slot.value.typeTag && changed.flags==slot.value.flags);
            CHECK(editAndWait(debugger,stop.stop->identity,index,numericText(slot),&restored));CHECK(restored==slot.value);
            instanceEdited=true;break;
        }
    }
    CHECK(instanceEdited);
    // Native breakpoints retain distinct stop authority; no archive bytes change.
    stop=debugger.gameMakerSnapshot();
    const auto staleOwner=stop.stop->identity;
    const auto hook=stop.runnerBase+NubbyGameMakerRunner().interpreterEntry.rva;
    CHECK(!debugger.addBreakpoint(hook));
    const auto nativeAddress=hook+NubbyGameMakerRunner().interpreterEntry.byteCount;
    CHECK(debugger.addBreakpoint(nativeAddress));
    CHECK(debugger.setGameMakerBreakpoints(binary.contentHash(),{},error));
    CHECK(debugger.gameMakerCommand(GmlControlCommand::Continue,staleOwner,error));
    bool nativeHit=false;
    for(int i=0;i<3000;++i){auto n=debugger.snapshot();if(n.state==DbgState::Paused && n.regs.rip==nativeAddress){nativeHit=true;break;}Sleep(10);}
    CHECK(nativeHit);CHECK(!debugger.gameMakerSnapshot().stop);
    CHECK(!debugger.editGameMakerNumeric(staleOwner,debugger.gameMakerSnapshot().revision,0,"0",error));
    CHECK(debugger.removeBreakpoint(nativeAddress));
    debugger.cont();
    // Drain and unload without detaching native debugging; then reconnect a new nonce.
    debugger.disconnectGameMaker();
    for(int i=0;i<3000;++i){auto s=debugger.gameMakerSnapshot();if(s.state==GameMakerSessionState::Disconnected || s.state==GameMakerSessionState::Inert || s.state==GameMakerSessionState::Failed)break;Sleep(10);}
    status(debugger);
    CHECK(debugger.gameMakerSnapshot().state==GameMakerSessionState::Disconnected);
    CHECK(!debugger.gameMakerSnapshot().mappingRetained);
    CHECK(debugger.connectGameMaker(archive,path,binary.contentHash(),breakpoints,error));
    stop=waitStop(debugger,0,45000);CHECK(stop.stop);
    if(stop.stop)CHECK(stop.stop->identity.helperGeneration!=staleOwner.helperGeneration);
    CHECK(debugger.setGameMakerBreakpoints(binary.contentHash(),{},error));
    CHECK(debugger.gameMakerCommand(GmlControlCommand::Continue,stop.stop->identity,error));
    for(int i=0;i<100 && debugger.snapshot().state!=DbgState::Running;++i)Sleep(10);
    benchmark(pid,"gml-attached-idle",&debugger);
    const auto dormant=std::find_if(archive->code.begin(),archive->code.end(),[](const auto& c){return c.name=="gml_Script_scr_GiveMoney";});
    CHECK(dormant!=archive->code.end());
    if(dormant!=archive->code.end()) {
        std::vector<GmlSavedBreakpoint> armed={{{binary.contentHash(),dormant->index,dormant->entryOffset,dormant->parentIndex},true}};
        CHECK(debugger.setGameMakerBreakpoints(binary.contentHash(),armed,error));Sleep(100);
        benchmark(pid,"gml-armed-unhit-scr_GiveMoney",&debugger);
    }
    CHECK(debugger.gameMakerCommand(GmlControlCommand::Pause,{},error));
    stop=waitStop(debugger,0,45000);CHECK(stop.stop);
    debugger.detach();
    const auto state=debugger.gameMakerSnapshot();
    std::printf("DETACH state=%u retained=%u error=%s\n",unsigned(state.state),unsigned(state.mappingRetained),state.error.c_str());
    CHECK(debugger.snapshot().state==DbgState::Detached);
    HANDLE process=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    CHECK(process && WaitForSingleObject(process,1000)==WAIT_TIMEOUT);if(process)CloseHandle(process);
    std::printf("live_debugger_test: %s (%d failures)\n",failures?"FAILED":"PASSED",failures);
    return failures?1:0;
}
