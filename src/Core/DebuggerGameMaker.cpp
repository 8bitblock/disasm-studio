#include "Debugger.h"
#include "GameMakerArchive.h"
#include "GameMakerHelperImage.h"
#include "GameMakerRunner.h"
#include "GameMakerInspection.h"
#include "GameMakerHookMutation.h"
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <future>
#include <limits>
#include <utility>
#pragma comment(lib, "bcrypt.lib")

namespace ds {
namespace {
std::array<GmlRunnerHookSite,4> hookSites(const GmlRunnerProfile& p) {
    return {p.instructionDispatch,p.interpreterEntry,p.instanceConstructor,p.instanceDestructor};
}
std::wstring gmlWide(const std::string& text) {
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), (int)text.size(), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(n, 0);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), (int)text.size(), out.data(), n);
    return out;
}
bool remoteRead(void* owner, uint64_t address, void* out, size_t count) {
    SIZE_T got = 0;
    return address && count && count <= UINT64_MAX-address &&
        ReadProcessMemory((HANDLE)owner, (LPCVOID)address, out, count, &got) && got == count;
}
bool remoteWrite(HANDLE process, uint64_t address, const void* bytes, size_t count) {
    SIZE_T wrote = 0;
    if (!WriteProcessMemory(process, (LPVOID)address, bytes, count, &wrote) || wrote != count) return false;
    // A successful write must not be followed by a throwing verification
    // allocation, especially while an instruction hook owns these bytes.
    std::array<uint8_t,4096> check{};
    for(size_t offset=0;offset<count;) {
        const size_t chunk=(std::min)(check.size(),count-offset);
        if(!remoteRead(process,address+offset,check.data(),chunk) ||
           std::memcmp(static_cast<const uint8_t*>(bytes)+offset,check.data(),chunk))return false;
        offset+=chunk;
    }
    return true;
}
bool publishControl(HANDLE process, uint64_t address, const GmlHelperControl& control) {
    // The target is frozen. Publish the sequence last so a helper copy that was
    // interrupted by this event detects a changed sequence and discards its copy.
    constexpr size_t sequence=offsetof(GmlHelperControl,commandSequence);
    constexpr size_t tail=sequence+sizeof(control.commandSequence);
    const auto* bytes=(const uint8_t*)&control;
    return remoteWrite(process,address,bytes,sequence) &&
        remoteWrite(process,address+tail,bytes+tail,sizeof(control)-tail) &&
        remoteWrite(process,address+sequence,&control.commandSequence,sizeof(control.commandSequence));
}
bool replaceCode(HANDLE process, uint64_t address, std::span<const uint8_t> expected,
                 std::span<const uint8_t> replacement, DWORD* originalProtection=nullptr) {
    GmlHookMutationIo io{process,remoteRead,
        [](void* owner,uint64_t at,const void* bytes,size_t n){return remoteWrite((HANDLE)owner,at,bytes,n);},
        [](void* owner,uint64_t at,size_t n,uint32_t next,uint32_t* old){
            DWORD previous=0;const bool ok=!!VirtualProtectEx((HANDLE)owner,(LPVOID)at,n,next,&previous);
            if(ok)*old=previous;return ok;
        },
        [](void* owner,uint64_t at,size_t n){return !!FlushInstructionCache((HANDLE)owner,(LPCVOID)at,n);}};
    const auto result=MutateGmlHookBytes(io,address,expected,replacement,PAGE_EXECUTE_READWRITE);
    if(originalProtection && result.originalProtectionKnown)*originalProtection=result.originalProtection;
    return result.success;
}
bool readBoundedFile(const std::string& path, uint64_t maximum, std::vector<uint8_t>& bytes,
                     AttachedFileIdentity* identity, std::string& error) {
    const auto wide = gmlWide(path);
    HANDLE file = CreateFileW(wide.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) { error = "Cannot open the runner/archive for verified reading."; return false; }
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    bool ok = GetFileInformationByHandle(file,&info) && GetFileSizeEx(file,&size) &&
        size.QuadPart > 0 && uint64_t(size.QuadPart) <= maximum && !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    if (ok) {
        bytes.resize((size_t)size.QuadPart);
        DWORD got = 0;
        ok = ReadFile(file,bytes.data(),(DWORD)bytes.size(),&got,nullptr) && got == bytes.size();
    }
    if (ok && identity) {
        *identity = {true,info.dwVolumeSerialNumber,
            (uint64_t(info.nFileIndexHigh)<<32)|info.nFileIndexLow,
            uint64_t(size.QuadPart),
            (uint64_t(info.ftLastWriteTime.dwHighDateTime)<<32)|info.ftLastWriteTime.dwLowDateTime};
    }
    CloseHandle(file);
    if (!ok) error = "Runner/archive file is unavailable, changed, or exceeds the bounded read limit.";
    return ok;
}
struct GmlPreparation {
    std::string helperPath, error;
    const GmlRunnerProfile* profile = nullptr;
    AttachedFileIdentity runnerIdentity;
    std::unique_ptr<GmlHelperInitConfig> init;
};
GmlPreparation prepareGml(const std::string& runner, const std::string& archivePath,
    uint64_t archiveHash, std::shared_ptr<const GameMakerArchive> archive) {
    GmlPreparation out;
    std::vector<uint8_t> bytes;
    if (!readBoundedFile(runner,64u*1024u*1024u,bytes,&out.runnerIdentity,out.error)) return out;
    out.profile = MatchGameMakerRunner(GameMakerHelperSha256(bytes));
    if (!out.profile) { out.error = "This executable hash has no verified built-in GameMaker adapter."; return out; }
    if (!readBoundedFile(archivePath,128u*1024u*1024u,bytes,nullptr,out.error)) return out;
    uint64_t hash = 1469598103934665603ull;
    for (auto b:bytes) { hash ^= b; hash *= 1099511628211ull; }
    hash ^= bytes.size(); hash *= 1099511628211ull;
    if (hash != archiveHash || GameMakerHelperSha256(bytes) !=
        "b00a69fbe77812e6caff3aa0250c16d24d1e16e9c70cd563bd69eca27506b982") {
        out.error = "The archive does not match the inspected Nubby build and loaded document."; return out;
    }
    if (!archive || !archive->ok || !archive->bytecodeSupported || archive->code.empty() ||
        archive->code.size() > kGmlMaxHelperCodes) {
        out.error = "Archive bytecode is unsupported or exceeds the helper code-map capacity."; return out;
    }
    if (!ExtractEmbeddedGameMakerHelper(out.helperPath,out.error)) return out;
    out.init = std::make_unique<GmlHelperInitConfig>();
    out.init->archiveHash = archiveHash;
    out.init->codeCount = (uint32_t)archive->code.size();
    for (const auto& code:archive->code) {
        if (code.index >= out.init->codeCount || !code.instructionsComplete) {
            out.error = "A code entry has an unsupported/incomplete instruction body."; out.init.reset(); return out;
        }
        out.init->codes[code.index] = {code.index,code.parentIndex,code.entryOffset,code.bytecodeLength};
    }
    return out;
}
bool validLocation(const GameMakerArchive& archive, uint64_t hash, const GmlCodeLocation& location) {
    if (!GmlLocationHasIdentity(location) || location.archiveHash != hash || location.codeIndex >= archive.code.size()) return false;
    const auto& code = archive.code[location.codeIndex];
    return code.parentIndex == location.parentCodeIndex && location.byteOffset >= code.entryOffset &&
        location.byteOffset < code.bytecodeLength && archive.isInstructionOffset(code.bytecodeOffset+location.byteOffset);
}
bool validFrameLocation(const GameMakerArchive& archive,uint64_t hash,const GmlHelperFrame& frame) {
    if (!(frame.flags & kGmlFrameLocationIsContinuation)) return validLocation(archive,hash,frame.location);
    const auto& location=frame.location;
    if (!GmlLocationHasIdentity(location) || location.archiveHash!=hash || location.codeIndex>=archive.code.size())return false;
    const auto& code=archive.code[location.codeIndex];
    // A suspended caller contains the return continuation. Preserve that fact;
    // code-end is valid here, but can never be planted as an instruction stop.
    return location.parentCodeIndex==code.parentIndex && location.byteOffset>=code.entryOffset &&
        location.byteOffset<=code.bytecodeLength &&
        (location.byteOffset==code.bytecodeLength || archive.isInstructionOffset(code.bytecodeOffset+location.byteOffset));
}
bool provePausedFrame(const GmlRunnerReader& reader,uint64_t base,const GmlHelperStop& stop,
                      const GmlHelperFrame& wanted) {
    if (!stop.frameCount) return false;
    const auto& top=stop.frames[0];
    GmlRunnerContextView context;
    if (!ReadGmlRunnerContext(reader,base,top.frameAddress,top.location.byteOffset,top.operandStackTop,context))return false;
    uint64_t seen[kGmlMaxFrames]{};uint32_t visits=0,frames=0;
    while(context.address && visits<kGmlMaxFrames) {
        for(uint32_t i=0;i<visits;++i)if(seen[i]==context.address)return false;
        seen[visits++]=context.address;
        if(context.logicalDepth>=kGmlMaxFrames)return false;
        auto code=context.code;auto anchor=context.anchor;auto local=context.localObject;auto self=context.self;
        auto arguments=context.arguments;auto argumentCount=context.argumentCount;auto offset=context.byteOffset;
        for(uint32_t remaining=context.logicalDepth+1;remaining && frames++<kGmlMaxFrames;--remaining) {
            if(context.address==wanted.frameAddress && anchor==wanted.logicalAnchor) {
                return code.codeIndex==wanted.location.codeIndex && offset==wanted.location.byteOffset &&
                    local==wanted.localObject && self==wanted.selfObject &&
                    arguments==wanted.arguments && argumentCount==wanted.argumentCount;
            }
            if(remaining==1)break;
            GmlRunnerSavedFrameView saved;
            if(!ReadGmlRunnerSavedFrame(reader,base,context,anchor,saved))return false;
            anchor=saved.previousAnchor;code=saved.code;local=saved.localObject;self=saved.self;
            arguments=saved.arguments;argumentCount=saved.argumentCount;offset=saved.returnOffset;
        }
        if(!context.nativeParent)break;
        uint32_t pc=0;
        if(!reader.copy(context.nativeParent+0x8c,&pc,sizeof(pc)) ||
            !ReadGmlRunnerContext(reader,base,context.nativeParent,pc,0,context))return false;
    }
    return false;
}
bool proveNumericOwner(const GmlRunnerReader& reader,uint64_t base,const GmlHelperStop& stop,
                       const GmlHelperNumericSlot& slot) {
    if(!slot.ownerObject)return false;
    if(slot.scope==GmlVariableScope::Global) {
        uint64_t global=0;
        if(!reader.copy(base+NubbyGameMakerRunner().globalObjectRva,&global,sizeof(global)) || global!=slot.ownerObject)return false;
    } else {
        bool found=false;
        for(uint32_t i=0;i<stop.frameCount;++i) {
            const auto& frame=stop.frames[i];
            const bool match=slot.scope==GmlVariableScope::FrameLocal ?
                (slot.frameId==frame.frameId && slot.ownerObject==frame.localObject):
                (slot.instanceId==frame.instanceId && slot.ownerObject==frame.selfObject);
            if(match && provePausedFrame(reader,base,stop,frame)){found=true;break;}
        }
        if(!found)return false;
    }
    GmlRunnerObjectView object;GmlRunnerVariableMapView map;
    if(!ReadGmlRunnerObject(reader,base,slot.ownerObject,object) || object.objectIndex!=slot.objectIndex ||
       object.instanceNumber!=slot.runtimeInstanceNumber ||
       !ReadGmlRunnerVariableMap(reader,object.variableMap,map))return false;
    uint32_t matches=0,live=0;
    for(uint32_t i=0;i<map.capacity;++i) {
        GmlRunnerVariableEntry entry;
        if(!ReadGmlRunnerVariableEntry(reader,map,i,entry))return false;
        if(!entry.valueAddress)continue;
        ++live;
        if(entry.runtimeId==slot.runtimeVariableId) {
            if(entry.valueAddress!=slot.address)return false;
            ++matches;
        }
    }
    if(live!=map.count || matches!=1)return false;
    if(slot.nameLength) {
        char name[64]{};
        if(slot.nameLength>=sizeof(name) || !ReadGmlRunnerVariableName(reader,base,slot.runtimeVariableId,name,sizeof(name)) ||
           std::strlen(name)!=slot.nameLength || std::memcmp(name,slot.name,slot.nameLength))return false;
    }
    return true;
}
uint64_t allocateNear(HANDLE process, uint64_t target) {
    SYSTEM_INFO info{}; GetSystemInfo(&info);
    const uint64_t granularity = info.dwAllocationGranularity;
    const uint64_t center = target & ~(granularity-1);
    for (uint64_t distance=granularity; distance < 0x7fff0000; distance+=granularity) {
        for (bool below:{false,true}) {
            if (below && distance >= center) continue;
            const uint64_t candidate = below ? center-distance : center+distance;
            MEMORY_BASIC_INFORMATION region{};
            if (!VirtualQueryEx(process,(LPCVOID)candidate,&region,sizeof(region)) || region.State!=MEM_FREE) continue;
            if (auto ptr=VirtualAllocEx(process,(LPVOID)candidate,granularity,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE))
                return (uint64_t)ptr;
        }
    }
    return 0;
}
} // namespace

class GameMakerSession {
public:
    DebugTargetIdentity target;
    DbgModule runner, helper;
    std::future<GmlPreparation> preparation;
    GmlPreparation prepared;
    std::shared_ptr<const GameMakerArchive> archive;
    uint64_t hash=0, nonce=0, generation=0, commandSequence=0, stopSequence=0;
    uint64_t helperBase=0, helperSize=0, remotePath=0, mailbox=0, config=0, relay=0;
    uint64_t remoteHostHandle=0;
    HANDLE loaderThread=nullptr, initThread=nullptr, shutdownThread=nullptr;
    uint64_t startedAt=0;
    std::array<std::array<uint8_t,16>,4> patches{};
    std::array<bool,4> hooks{};
    std::array<DWORD,4> originalProtection{};
    std::vector<bool> observedCodes;
    uint64_t lifetimesAddress=0;
    uint32_t lifetimesCapacity=0;
    uint32_t selectedObject=kGmlNoCodeIndex;
    uint64_t selectedInstance=0;
    bool inspectionPending=false;
    std::vector<GmlCodeLocation> breakpoints;
    bool breakpointUpdate=false, disableRequested=false, wakeRequested=false;
    bool disablePublished=false;
    GmlControlCommand runningCommand=GmlControlCommand::None;
    GmlControlCommand resumeCommand=GmlControlCommand::None;
    struct Edit { GmlPauseIdentity owner; uint64_t revision; uint32_t slot; std::string value; };
    std::vector<Edit> edits;
    ~GameMakerSession() {
        if(loaderThread) CloseHandle(loaderThread);
        if(initThread) CloseHandle(initThread);
        if(shutdownThread) CloseHandle(shutdownThread);
    }
};

GameMakerSessionSnapshot Debugger::gameMakerSnapshot() {
    std::lock_guard lock(mtx_); return gmlSnapshot_;
}
bool Debugger::connectGameMaker(std::shared_ptr<const GameMakerArchive> archive,
    const std::string& path, uint64_t hash, const std::vector<GmlSavedBreakpoint>& breakpoints,
    std::string& error) {
    std::lock_guard lock(mtx_);
    if (cleanupOnly_ || pendingCommand_.command == Cmd::Detach) { error="Native cleanup is pending; Retry Detach first."; return false; }
    if ((state_!=DbgState::Running && state_!=DbgState::Paused) || isWow64_ || !archive || !archive->ok || !hash) {
        error="Attach to the x64 Nubby process and open its data.win first."; return false;
    }
    if (gmlSession_) { error="A GameMaker connection already belongs to this native session; detach before reconnecting."; return false; }
    const auto runner=std::find_if(dbgModules_.begin(),dbgModules_.end(),[](const DbgModule& m){
        return _stricmp(m.name.c_str(),"NNF_FULLVERSION.exe")==0;
    });
    if (runner==dbgModules_.end() || !runner->fileIdentity.valid) {
        error="The attached image is not the installed Nubby runner with a verified backing file."; return false;
    }
    auto session=std::make_shared<GameMakerSession>();
    session->target={pid_,sessionGeneration_}; session->runner=*runner;
    session->archive=std::move(archive); session->hash=hash; session->generation=++gmlGeneration_;
    session->observedCodes.resize(session->archive->code.size());
    if (BCryptGenRandom(nullptr,(PUCHAR)&session->nonce,sizeof(session->nonce),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0 || !session->nonce) {
        error="Could not create the private helper session nonce."; return false;
    }
    if (breakpoints.size()>kGmlMaxBreakpoints) {error="Too many GML breakpoints.";return false;}
    for(const auto& bp:breakpoints) if(bp.enabled) {
        if(!validLocation(*session->archive,hash,bp.location)) {error="A saved GML breakpoint no longer identifies an exact instruction.";return false;}
        session->breakpoints.push_back(bp.location);
    }
    session->preparation=std::async(std::launch::async,prepareGml,runner->path,path,hash,session->archive);
    gmlSnapshot_={}; gmlSnapshot_.target=session->target; gmlSnapshot_.generation=session->generation;
    gmlSnapshot_.archiveHash=hash; gmlSnapshot_.archive=session->archive;
    gmlSnapshot_.runnerBase=runner->base; gmlSnapshot_.state=GameMakerSessionState::Preparing;
    gmlSnapshot_.status="Verifying runner/archive and extracting the embedded helper";
    gmlSnapshot_.requestedBreakpoints=(uint32_t)session->breakpoints.size();
    gmlSession_=std::move(session);
    if(state_==DbgState::Paused) {if(pendingCommand_.command==Cmd::None)pendingCommand_={Cmd::ServiceWrites,0,controlEpoch_};cmdCv_.notify_all();}
    return true;
}
bool Debugger::setGameMakerBreakpoints(uint64_t hash,const std::vector<GmlSavedBreakpoint>& breakpoints,std::string& error) {
    DebugTargetIdentity target;
    {
        std::lock_guard lock(mtx_);
    if (cleanupOnly_ || pendingCommand_.command == Cmd::Detach) { error="Native cleanup is pending; Retry Detach first."; return false; }
        if(!gmlSession_ || gmlSession_->hash!=hash || breakpoints.size()>kGmlMaxBreakpoints) {
            error="The breakpoint list does not belong to this GameMaker connection.";return false;
        }
        std::vector<GmlCodeLocation> next;
        for(const auto& bp:breakpoints) if(bp.enabled) {
            if(!validLocation(*gmlSession_->archive,hash,bp.location)) {error="A GML breakpoint is not an exact archive instruction.";return false;}
            next.push_back(bp.location);
        }
        gmlSession_->breakpoints=std::move(next);gmlSession_->breakpointUpdate=true;
        gmlSnapshot_.requestedBreakpoints=(uint32_t)gmlSession_->breakpoints.size();
        target=gmlSession_->target;
        if(state_==DbgState::Paused){if(pendingCommand_.command==Cmd::None)pendingCommand_={Cmd::ServiceWrites,0,controlEpoch_};cmdCv_.notify_all();return true;}
    }
    requestTraceSyncBreak(target); return true;
}
bool Debugger::gameMakerCommand(GmlControlCommand command,GmlPauseIdentity expected,std::string& error) {
    DebugTargetIdentity target;
    {
        std::lock_guard lock(mtx_);
    if (cleanupOnly_ || pendingCommand_.command == Cmd::Detach) { error="Native cleanup is pending; Retry Detach first."; return false; }
        if(!gmlSession_ || !gmlSnapshot_.ready()) {error="GameMaker instruction debugging is not ready.";return false;}
        target=gmlSession_->target;
        if(command==GmlControlCommand::Pause && state_==DbgState::Running) {
            gmlSession_->runningCommand=command;
        } else {
            if(state_!=DbgState::Paused || !gmlSnapshot_.stop ||
               !GmlPauseIdentityMatches(expected,gmlSnapshot_.stop->identity) ||
               activeTid_!=expected.tid || command<GmlControlCommand::Continue || command>GmlControlCommand::StepOut ||
               command==GmlControlCommand::Pause) {
                error="This command requires the current GML stop and its original thread.";return false;
            }
            gmlSession_->resumeCommand=command;
            pendingCommand_={Cmd::GmlResume,0,controlEpoch_,expected.tid};cmdCv_.notify_all();return true;
        }
    }
    requestTraceSyncBreak(target);return true;
}
bool Debugger::editGameMakerNumeric(GmlPauseIdentity expected,uint64_t revision,uint32_t slot,std::string value,std::string& error) {
    std::lock_guard lock(mtx_);
    if (cleanupOnly_ || pendingCommand_.command == Cmd::Detach) { error="Native cleanup is pending; Retry Detach first."; return false; }
    if(!gmlSession_ || state_!=DbgState::Paused || !gmlSnapshot_.stop || activeTid_!=expected.tid ||
        !GmlPauseIdentityMatches(expected,gmlSnapshot_.stop->identity) || revision!=gmlSnapshot_.revision || slot>=gmlSnapshot_.stop->numericSlotCount ||
        value.size()>128 || gmlSession_->edits.size()>=16) {
        error="Numeric edit rejected: the GML stop, thread, slot, or request lifetime is invalid.";return false;
    }
    gmlSession_->edits.push_back({expected,revision,slot,std::move(value)});
    if(pendingCommand_.command==Cmd::None)pendingCommand_={Cmd::ServiceWrites,0,controlEpoch_};cmdCv_.notify_all();return true;
}
bool Debugger::inspectGameMakerInstance(GmlPauseIdentity expected,uint32_t objectIndex,uint64_t instanceId,std::string& error) {
    std::lock_guard lock(mtx_);
    if (cleanupOnly_ || pendingCommand_.command == Cmd::Detach) { error="Native cleanup is pending; Retry Detach first."; return false; }
    if(!gmlSession_ || state_!=DbgState::Paused || !gmlSnapshot_.stop || activeTid_!=expected.tid ||
        !GmlPauseIdentityMatches(expected,gmlSnapshot_.stop->identity) ||
        (instanceId && objectIndex!=kGmlNoCodeIndex) ||
        (objectIndex!=kGmlNoCodeIndex && objectIndex>=gmlSession_->archive->objects.size())) {
        error="Instance inspection requires the current GML stop and an exact object or instance selection.";return false;
    }
    gmlSession_->selectedObject=objectIndex;gmlSession_->selectedInstance=instanceId;
    gmlSession_->inspectionPending=true;
    if(pendingCommand_.command==Cmd::None)pendingCommand_={Cmd::ServiceWrites,0,controlEpoch_};cmdCv_.notify_all();return true;
}
void Debugger::disconnectGameMaker() {
    DebugTargetIdentity target;
    {
        std::lock_guard lock(mtx_);if(cleanupOnly_ || pendingCommand_.command == Cmd::Detach || !gmlSession_)return;
        gmlSession_->disableRequested=true;target=gmlSession_->target;
        if(state_==DbgState::Paused){if(pendingCommand_.command==Cmd::None)pendingCommand_={Cmd::ServiceWrites,0,controlEpoch_};cmdCv_.notify_all();return;}
    }
    requestTraceSyncBreak(target);
}
bool Debugger::gameMakerOwnsRangeLocked(uint64_t address,uint64_t size) const {
    if(!size || size>UINT64_MAX-address)return true;
    return std::any_of(gmlOwnedRanges_.begin(),gmlOwnedRanges_.end(),[&](auto r){
        return address<r.first+r.second && r.first<address+size;
    });
}
bool Debugger::gameMakerBreakpointConflictLocked(uint64_t address,uint64_t size) const {
    const auto within=[&](uint64_t a){return a>=address && a-address<size;};
    if(runtimeTempBpAddr_ && within(*runtimeTempBpAddr_))return true;
    for(const auto& bp:pendingBpAdds_)if(within(bp.va))return true;
    const auto has=[&](const auto& map){for(const auto& kv:map)if(within(kv.first))return true;return false;};
    if(has(bps_)||has(traceBps_)||has(antiTraps_)||has(dllTargetBps_)||has(networkProbeBps_)||
       has(networkReturnBps_)||has(authorizationBps_)||has(authorizationReturnBps_))return true;
    for(const auto& slot:hwSlots_)if(slot.used && within(slot.addr))return true;
    for(const auto& slot:pendingHwAdds_)if(within(slot.addr))return true;
    return false;
}

// The entire routine runs on the sole debug-event thread. Remote-thread handles
// are polled, never waited on; code changes require eventHeld. UI mutations use
// mtx_, so a publication cannot race a command or lose its pause identity.
void Debugger::serviceGameMaker(bool eventHeld) {
    std::unique_lock lock(mtx_);
    auto session=gmlSession_;
    if(!session || !hProcess_ || !DebugTargetIdentityMatches(session->target,{pid_,sessionGeneration_}))return;
    auto& s=*session;auto& view=gmlSnapshot_;HANDLE process=(HANDLE)hProcess_;
    const auto publish=[&](GameMakerSessionState state,const char* text){view.state=state;view.status=text;++view.revision;};
    const auto fail=[&](std::string error){view.state=GameMakerSessionState::Failed;view.error=std::move(error);view.stop.reset();view.capabilities.runtimeVerified=false;++view.revision;};
    if(eventHeld && view.ready()) {
        const auto runner=std::find_if(dbgModules_.begin(),dbgModules_.end(),[&](const auto& module){
            return module.base==s.runner.base && module.loadGeneration==s.runner.loadGeneration &&
                SameAttachedFileIdentity(module.fileIdentity,s.runner.fileIdentity);
        });
        const auto helper=std::find_if(dbgModules_.begin(),dbgModules_.end(),[&](const auto& module){
            return module.base==s.helperBase && module.size==s.helperSize && module.loadGeneration==s.helper.loadGeneration &&
                SameAttachedFileIdentity(module.fileIdentity,s.helper.fileIdentity);
        });
        if(runner==dbgModules_.end() || helper==dbgModules_.end()) {
            lock.unlock();cleanupGameMakerOwned(true);lock.lock();
            fail("The runner/helper module lifetime changed; GML stop authority was revoked.");return;
        }
    }
    if(s.disableRequested && eventHeld &&
       (view.ready() || view.state==GameMakerSessionState::Installing ||
        view.state==GameMakerSessionState::Failed || view.state==GameMakerSessionState::Inert)) {
        lock.unlock();cleanupGameMakerOwned(true);return;
    }
    if(view.state==GameMakerSessionState::Disabling) {
        if(s.shutdownThread) {
            DWORD result=STILL_ACTIVE;
            if(!GetExitCodeThread(s.shutdownThread,&result)) {fail("Could not verify helper shutdown completion.");return;}
            if(result==STILL_ACTIVE)return;
            if(!eventHeld){lock.unlock();requestTraceSyncBreak(session->target);return;}
            const bool mapped=std::any_of(dbgModules_.begin(),dbgModules_.end(),[&](const auto& m){return m.base==s.helperBase;});
            if(result || mapped) {
                publish(GameMakerSessionState::Inert,"GML hooks restored; helper unload could not be proved, retaining its mapping");return;
            }
            if(s.mailbox)VirtualFreeEx(process,(LPVOID)s.mailbox,0,MEM_RELEASE);
            if(s.relay)VirtualFreeEx(process,(LPVOID)s.relay,0,MEM_RELEASE);
            gmlOwnedRanges_.clear();view.mappingRetained=false;
            publish(GameMakerSessionState::Disconnected,"GML callbacks drained and helper unloaded");gmlSession_.reset();return;
        }
        if(eventHeld) {lock.unlock();cleanupGameMakerOwned(true);return;}
        // A stop was released so its callback can drain. A fresh native event
        // is required to prove both the callback count and every thread RIP.
        lock.unlock();requestTraceSyncBreak(session->target);return;
    }
    if(view.state==GameMakerSessionState::Preparing) {
        if(s.preparation.wait_for(std::chrono::milliseconds(0))!=std::future_status::ready)return;
        try{s.prepared=s.preparation.get();}catch(const std::exception& e){fail(e.what());return;}
        if(s.disableRequested) {
            publish(GameMakerSessionState::Disconnected,"GameMaker setup cancelled before target mutation");gmlSession_.reset();return;
        }
        if(!s.prepared.error.empty() || !s.prepared.init){fail(s.prepared.error);return;}
        if(!SameAttachedFileIdentity(s.runner.fileIdentity,s.prepared.runnerIdentity)){fail("The runner backing file changed after attachment.");return;}
        view.runnerName=std::string(s.prepared.profile->name);
        view.capabilities.adapterId=s.prepared.profile->adapterId;
        view.capabilities.supported=s.prepared.profile->capabilityMask;
        view.capabilities.executableVerified=view.capabilities.archiveVerified=true;
        publish(GameMakerSessionState::Loading,"Loading the verified embedded helper; continue native execution if paused");
    }
    if(view.state==GameMakerSessionState::Loading && !s.loaderThread) {
        if(s.disableRequested) {publish(GameMakerSessionState::Disconnected,"GameMaker setup cancelled before helper loading");gmlSession_.reset();return;}
        if(!eventHeld) {lock.unlock();requestTraceSyncBreak(session->target);return;}
        const char* error=nullptr;
        if(!ValidateGmlRunnerImage({process,remoteRead},s.runner.base,*s.prepared.profile,&error)) {
            fail(error?error:"Runner runtime validation failed.");return;
        }
        // Resolve in the target image, including KernelBase's implementation;
        // no assumption that system DLL addresses equal the host's addresses.
        uint64_t loadLibrary=0;
        for(const char* dll:{"kernelbase.dll","kernel32.dll"})for(const auto& module:dbgModules_)
            if(_stricmp(module.name.c_str(),dll)==0 && !loadLibrary)
                loadLibrary=resolveMappedExport(module.base,module.size,"LoadLibraryW");
        if(!loadLibrary){fail("Cannot resolve the target's LoadLibraryW implementation.");return;}
        const auto path=gmlWide(s.prepared.helperPath);
        s.remotePath=(uint64_t)VirtualAllocEx(process,nullptr,(path.size()+1)*2,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        if(!s.remotePath || !remoteWrite(process,s.remotePath,path.c_str(),(path.size()+1)*2)) {fail("Could not prepare the helper loader path.");return;}
        s.loaderThread=CreateRemoteThread(process,nullptr,0,(LPTHREAD_START_ROUTINE)loadLibrary,(LPVOID)s.remotePath,0,nullptr);
        if(!s.loaderThread){fail("The target rejected the helper loader thread.");return;}
        s.startedAt=GetTickCount64();return;
    }
    if(view.state==GameMakerSessionState::Loading && s.loaderThread) {
        DWORD code=STILL_ACTIVE;
        if(!GetExitCodeThread(s.loaderThread,&code)){fail("Cannot inspect the helper loader completion.");return;}
        if(code==STILL_ACTIVE)return;
        if(!eventHeld){lock.unlock();requestTraceSyncBreak(session->target);return;}
        const auto wanted=gmlWide(s.prepared.helperPath);
        for(const auto& module:dbgModules_) if(_wcsicmp(gmlWide(module.path).c_str(),wanted.c_str())==0) {
            s.helper=module;s.helperBase=module.base;s.helperSize=module.size;break;
        }
        if(!s.helperBase){fail("The loader exited without a verified helper module event.");return;}
        CloseHandle(s.loaderThread);s.loaderThread=nullptr;
        VirtualFreeEx(process,(LPVOID)s.remotePath,0,MEM_RELEASE);s.remotePath=0;
        if(s.disableRequested) {
            s.disableRequested=false;view.mappingRetained=true;
            publish(GameMakerSessionState::Inert,"Helper load completed after cancellation; uninitialized mapping retained without hooks");return;
        }
        const uint64_t init=resolveMappedExport(s.helperBase,s.helperSize,"DsGmlInitialize");
        const uint64_t dispatch=resolveMappedExport(s.helperBase,s.helperSize,"DsGmlDispatchGate");
        const uint64_t entry=resolveMappedExport(s.helperBase,s.helperSize,"DsGmlEntryGate");
        const uint64_t constructor=resolveMappedExport(s.helperBase,s.helperSize,"DsGmlInstanceConstructorGate");
        const uint64_t destructor=resolveMappedExport(s.helperBase,s.helperSize,"DsGmlInstanceDestructorGate");
        if(!init||!dispatch||!entry||!constructor||!destructor){fail("Embedded helper exports are incomplete.");return;}
        s.mailbox=(uint64_t)VirtualAllocEx(process,nullptr,sizeof(GmlHelperMailbox),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        s.config=(uint64_t)VirtualAllocEx(process,nullptr,sizeof(GmlHelperInitConfig),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        s.relay=allocateNear(process,s.runner.base+s.prepared.profile->instructionDispatch.rva);
        if(!s.mailbox||!s.config||!s.relay){fail("Could not allocate bounded helper records and nearby instruction relays.");return;}
        std::array<uint8_t,64> relay{};
        const std::array<uint64_t,4> destinations={dispatch,entry,constructor,destructor};
        for(size_t i=0;i<destinations.size();++i){relay[i*16]=0xff;relay[i*16+1]=0x25;std::memcpy(relay.data()+i*16+6,&destinations[i],8);}
        DWORD protect=0;
        if(!remoteWrite(process,s.relay,relay.data(),relay.size()) ||
           !VirtualProtectEx(process,(LPVOID)s.relay,relay.size(),PAGE_EXECUTE_READ,&protect) ||
           !FlushInstructionCache(process,(LPCVOID)s.relay,relay.size())){fail("Could not publish instruction relays.");return;}
        HANDLE host=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),GetCurrentProcess(),process,&host,SYNCHRONIZE,FALSE,0)) {
            fail("Could not duplicate the debugger liveness handle.");return;
        }
        s.remoteHostHandle=(uint64_t)host;
        auto& config=*s.prepared.init;
        config.nonce=s.nonce;config.pid=s.target.pid;config.sessionGeneration=s.target.sessionGeneration;
        config.helperGeneration=s.generation;config.runnerBase=s.runner.base;config.runnerSize=s.runner.size;
        config.mailboxAddress=s.mailbox;config.hostProcessHandle=s.remoteHostHandle;
        config.dispatchContinuation=s.runner.base+s.prepared.profile->instructionDispatch.rva+s.prepared.profile->instructionDispatch.byteCount;
        config.entryContinuation=s.runner.base+s.prepared.profile->interpreterEntry.rva+s.prepared.profile->interpreterEntry.byteCount;
        config.dispatchRelayAddress=s.relay;config.entryRelayAddress=s.relay+16;
        config.instanceConstructorContinuation=s.runner.base+s.prepared.profile->instanceConstructor.rva+s.prepared.profile->instanceConstructor.byteCount;
        config.instanceDestructorContinuation=s.runner.base+s.prepared.profile->instanceDestructor.rva+s.prepared.profile->instanceDestructor.byteCount;
        config.instanceConstructorRelayAddress=s.relay+32;config.instanceDestructorRelayAddress=s.relay+48;
        auto mailbox=std::make_unique<GmlHelperMailbox>();
        mailbox->control.nonce=s.nonce;mailbox->control.commandSequence=++s.commandSequence;
        mailbox->control.command=GmlControlCommand::Continue;
        mailbox->control.breakpointCount=(uint32_t)s.breakpoints.size();
        std::copy(s.breakpoints.begin(),s.breakpoints.end(),mailbox->control.breakpoints);
        if(!remoteWrite(process,s.mailbox,mailbox.get(),sizeof(*mailbox)) ||
           !remoteWrite(process,s.config,&config,sizeof(config))) {fail("Could not initialize helper records.");return;}
        s.initThread=CreateRemoteThread(process,nullptr,0,(LPTHREAD_START_ROUTINE)init,(LPVOID)s.config,0,nullptr);
        if(!s.initThread){fail("The target rejected the helper initialization thread.");return;}
        view.helperBase=s.helperBase;view.mappingRetained=true;
        gmlOwnedRanges_.push_back({s.helperBase,s.helperSize});gmlOwnedRanges_.push_back({s.mailbox,sizeof(GmlHelperMailbox)});
        gmlOwnedRanges_.push_back({s.relay,64});gmlOwnedRanges_.push_back({s.config,sizeof(GmlHelperInitConfig)});
        publish(GameMakerSessionState::Initializing,"Initializing the verified runner adapter while pumping native debug events");return;
    }
    if(view.state==GameMakerSessionState::Initializing) {
        DWORD result=STILL_ACTIVE;
        if(!GetExitCodeThread(s.initThread,&result)){fail("Cannot inspect helper initialization completion.");return;}
        if(result==STILL_ACTIVE)return;
        if(!eventHeld){lock.unlock();requestTraceSyncBreak(session->target);return;}
        GmlHelperInitStatus status{};
        if(!remoteRead(process,s.config+offsetof(GmlHelperInitConfig,status),&status,sizeof(status)) ||
           status!=GmlHelperInitStatus::Ready || result) {
            CloseHandle(s.initThread);s.initThread=nullptr;
            if(s.remoteHostHandle) {
                HANDLE duplicate=nullptr;
                if(DuplicateHandle(process,(HANDLE)s.remoteHostHandle,GetCurrentProcess(),&duplicate,0,FALSE,
                    DUPLICATE_SAME_ACCESS|DUPLICATE_CLOSE_SOURCE) && duplicate)CloseHandle(duplicate);
                s.remoteHostHandle=0;
            }
            fail(status==GmlHelperInitStatus::AlreadyInitialized ?
                "An inert helper from an earlier session is still resident; restart the target before reconnecting.":
                "Helper initialization rejected the runner/layout/configuration.");return;
        }
        if(!remoteRead(process,s.config+offsetof(GmlHelperInitConfig,instanceLifetimesAddress),&s.lifetimesAddress,sizeof(s.lifetimesAddress)) ||
           !remoteRead(process,s.config+offsetof(GmlHelperInitConfig,instanceLifetimesCapacity),&s.lifetimesCapacity,sizeof(s.lifetimesCapacity)) ||
           !s.lifetimesAddress || s.lifetimesCapacity!=kGmlMaxInstanceLifetimes) {fail("Helper instance lifetime table was not published.");return;}
        gmlOwnedRanges_.push_back({s.lifetimesAddress,sizeof(GmlHelperInstanceLifetime)*s.lifetimesCapacity});
        CloseHandle(s.initThread);s.initThread=nullptr;s.remoteHostHandle=0;
        VirtualFreeEx(process,(LPVOID)s.config,0,MEM_RELEASE);
        std::erase_if(gmlOwnedRanges_,[&](auto range){return range.first==s.config;});s.config=0;
        publish(GameMakerSessionState::Installing,"Installing debugger-owned instruction boundary hooks");
        if(s.disableRequested) {lock.unlock();cleanupGameMakerOwned(true);return;}
    }
    if(view.state==GameMakerSessionState::Installing) {
        if(!eventHeld){lock.unlock();requestTraceSyncBreak(session->target);return;}
        const auto& profile=*s.prepared.profile;
        const char* error=nullptr;
        if(!ValidateGmlRunnerImage({process,remoteRead},s.runner.base,profile,&error)){fail(error?error:"Runner changed while loading the helper.");return;}
        const auto sites=hookSites(profile);
        for(const auto& site:sites) {
            const auto address=s.runner.base+site.rva;
            if(gameMakerBreakpointConflictLocked(address,site.byteCount)){fail("A native breakpoint or hook overlaps a required GML insertion site.");return;}
            for(const auto& [tid,handle]:threads_) {
                const auto rip=ctxReadRip(handle);
                if(!rip){fail("A target thread context is unreadable; instruction hooks were not installed.");return;}
                if(rip>address && rip<address+site.byteCount){fail("A thread is inside a displaced instruction; retry from a new session.");return;}
            }
        }
        for(size_t i=0;i<sites.size();++i) {
            const auto& site=sites[i];const uint64_t address=s.runner.base+site.rva;
            auto& patch=s.patches[i];patch.fill(0x90);patch[0]=0xe9;
            const int64_t distance=int64_t(s.relay+i*16)-int64_t(address+5);
            if(distance<INT32_MIN||distance>INT32_MAX){fail("The instruction relay is outside rel32 range.");return;}
            const int32_t relative=(int32_t)distance;std::memcpy(patch.data()+1,&relative,4);
            gmlOwnedRanges_.push_back({address,site.byteCount});
            // Ownership precedes mutation: protection restoration/cache flushing
            // can fail after the full jump has already been written.
            s.hooks[i]=true;
            if(!replaceCode(process,address,{site.original.data(),site.byteCount},{patch.data(),site.byteCount},&s.originalProtection[i])) {
                fail("A verified GML instruction hook could not be installed; disabling owned hooks.");
                lock.unlock();cleanupGameMakerOwned(true);return;
            }
        }
        view.boundBreakpoints=0;
        view.capabilities.runtimeVerified=true;
        publish(GameMakerSessionState::Running,"GML hooks installed; waiting for a validated instruction stop");
    }
    if(!eventHeld || !view.ready())return;
    if(s.breakpointUpdate || s.runningCommand!=GmlControlCommand::None) {
        // Pause commands from Running are published only while a native event
        // freezes every target thread. The helper validates publication sequence.
        auto control=std::make_unique<GmlHelperControl>();
        control->nonce=s.nonce;control->commandSequence=++s.commandSequence;
        control->command=s.runningCommand==GmlControlCommand::None ? GmlControlCommand::Continue:s.runningCommand;
        control->breakpointCount=(uint32_t)s.breakpoints.size();
        control->selectedObjectIndex=s.selectedObject;control->selectedInstanceId=s.selectedInstance;
        std::copy(s.breakpoints.begin(),s.breakpoints.end(),control->breakpoints);
        if(view.stop)control->expectedStop=view.stop->identity;
        if(!publishControl(process,s.mailbox,*control)){fail("Could not publish the GML control record.");return;}
        s.breakpointUpdate=false;s.runningCommand=GmlControlCommand::None;
        view.boundBreakpoints=(uint32_t)std::count_if(s.breakpoints.begin(),s.breakpoints.end(),[&](const auto& bp){return s.observedCodes[bp.codeIndex];});++view.revision;
    }
    if(!s.edits.empty()) {
        auto edits=std::move(s.edits);s.edits.clear();
        for(const auto& edit:edits) {
            if(!view.stop || state_!=DbgState::Paused || activeTid_!=edit.owner.tid ||
               !GmlPauseIdentityMatches(view.stop->identity,edit.owner) || edit.revision!=view.revision || edit.slot>=view.stop->numericSlotCount) {
                view.lastEdit="Rejected stale GML numeric edit.";continue;
            }
            const auto& slot=view.stop->numericSlots[edit.slot];GmlRValue fresh{};GmlNumericEditPlan plan;
            std::string error;GmlNumericLayout layout;layout.validated=true;layout.booleanEncoding=GmlBooleanEncoding::Float64;
            MEMORY_BASIC_INFORMATION region{};
            const DWORD allowed=PAGE_READWRITE|PAGE_WRITECOPY;
            if(!VirtualQueryEx(process,(LPCVOID)slot.address,&region,sizeof(region)) || region.State!=MEM_COMMIT ||
               !(region.Protect&allowed) || (region.Protect&(PAGE_GUARD|PAGE_NOACCESS)) ||
               slot.address<(uint64_t)region.BaseAddress || sizeof(GmlRValue)>region.RegionSize-(slot.address-(uint64_t)region.BaseAddress) ||
               !(slot.scope==GmlVariableScope::SessionInstance ?
                   ValidateGmlFrozenInstanceSlotOwnership({process,remoteRead},s.runner.base,s.lifetimesAddress,s.lifetimesCapacity,*view.stop,slot):
                   proveNumericOwner({process,remoteRead},s.runner.base,*view.stop,slot)) ||
               !remoteRead(process,slot.address,&fresh,sizeof(fresh)) ||
               !PlanGmlNumericEdit(edit.owner,view.stop->identity,slot,fresh,layout,edit.value,plan,&error)) {
                view.lastEdit=error.empty()?"Numeric storage is no longer an editable canonical value.":error;continue;
            }
            if(!remoteWrite(process,plan.valueAddress,plan.bytes.data(),plan.byteCount)) {
                (void)remoteWrite(process,plan.valueAddress,&plan.expectedValue.payload,plan.byteCount);
                view.lastEdit="Numeric write/readback failed; attempted to restore the original payload.";continue;
            }
            GmlRValue verify{};
            if(!remoteRead(process,slot.address,&verify,sizeof(verify)) || verify.flags!=fresh.flags || verify.typeTag!=fresh.typeTag) {
                view.lastEdit="Numeric value metadata failed verification.";continue;
            }
            auto next=std::make_shared<GmlHelperStop>(*view.stop);next->numericSlots[edit.slot].value=verify;view.stop=std::move(next);
            view.lastEdit="Numeric value written and verified; its type and metadata were preserved.";
        }
        ++view.revision;
    }
    if(s.inspectionPending && view.stop && state_==DbgState::Paused) {
        s.inspectionPending=false;
        auto next=std::make_shared<GmlHelperStop>(*view.stop);
        const auto inspectedStop=view.stop;
        const auto inspectedRevision=view.revision;
        const auto object=s.selectedObject;const auto instance=s.selectedInstance;
        std::string error;
        // Keep immutable publications readable by the renderer during bounded
        // remote map traversal. Queued edits retain their original revision.
        lock.unlock();
        const bool inspected=InspectGmlFrozenInstances({process,remoteRead},s.runner.base,s.lifetimesAddress,s.lifetimesCapacity,
            object,instance,*next,&error);
        lock.lock();
        if(gmlSession_!=session || view.stop!=inspectedStop || view.revision!=inspectedRevision)return;
        if(inspected) {
            view.stop=std::move(next);view.status="Instance variables inspected under the held GML event";
        } else view.error=error;
        ++view.revision;
    }
}

bool Debugger::acceptGameMakerException(uint32_t code,bool firstChance,uint32_t tid,
    uint32_t count,const uint64_t* parameters) {
    if(code!=kGmlStopExceptionCode || !firstChance || count!=5 || !parameters)return false;
    std::unique_lock lock(mtx_);
    if(!gmlSession_ || !gmlSnapshot_.ready())return false;
    const auto session=gmlSession_;
    auto& s=*gmlSession_;
    if(parameters[0]!=kGmlProtocolMagic || parameters[1]!=s.nonce || parameters[2]!=s.mailbox ||
       parameters[3]!=s.generation || parameters[4]<=s.stopSequence || !threads_.count(tid))return false;
    const auto reject=[&](const char* reason) {
        gmlSnapshot_.stop.reset();gmlSnapshot_.state=GameMakerSessionState::Failed;
        gmlSnapshot_.capabilities.runtimeVerified=false;
        gmlSnapshot_.error=reason;gmlSnapshot_.status="The claimed GML stop failed validation; edit authority revoked";
        s.disableRequested=true;++gmlSnapshot_.revision;return false;
    };
    auto stop=std::make_shared<GmlHelperStop>();
    if(!remoteRead(hProcess_,s.mailbox+offsetof(GmlHelperMailbox,stop),stop.get(),sizeof(*stop)))return reject("The GML stop record is unreadable.");
    GmlPauseIdentity expected{s.target.pid,tid,s.target.sessionGeneration,s.generation,parameters[4]};
    const auto validation=ValidateGmlHelperStop(*stop,s.nonce,expected,s.hash);
    if(!validation.valid || stop->adapterId!=s.prepared.profile->adapterId || stop->dispatchSiteId!=1 ||
       !validLocation(*s.archive,s.hash,stop->location))return reject("The GML stop identity, layout, adapter, or instruction location is invalid.");
    for(uint32_t i=0;i<stop->frameCount;++i)if(!validFrameLocation(*s.archive,s.hash,stop->frames[i]))return reject("A GML frame has an invalid archive continuation.");
    // Validate the top runtime code object by compiler name, CODE identity and
    // shared-body extent. Loaded operands are relocated, so raw equality is wrong.
    if(!stop->frameCount)return reject("The GML stop contains no current frame.");
    GmlRunnerContextView context;
    if(!ReadGmlRunnerContext({hProcess_,remoteRead},s.runner.base,stop->frames[0].frameAddress,
        stop->location.byteOffset,stop->frames[0].operandStackTop,context))return reject("The live GML interpreter context no longer validates.");
    const auto& archiveCode=s.archive->code[stop->location.codeIndex];
    char name[1024]{};
    if(context.code.codeIndex!=stop->location.codeIndex || context.code.entryOffset!=archiveCode.entryOffset ||
       context.code.bytecodeLength!=archiveCode.bytecodeLength ||
       !ReadGmlRunnerString({hProcess_,remoteRead},context.code.nameAddress,name,sizeof(name)) || name!=archiveCode.name)return reject("The runtime code object does not match the archive entry and shared body.");
    // The helper projected before RaiseException froze other threads. Recertify
    // registry membership and incarnation tokens under this held native event.
    std::string inspectionError;
    const auto selectedObject=s.selectedObject;const auto selectedInstance=s.selectedInstance;
    lock.unlock();
    const bool inspected=InspectGmlFrozenInstances({hProcess_,remoteRead},s.runner.base,s.lifetimesAddress,s.lifetimesCapacity,
        selectedObject,selectedInstance,*stop,&inspectionError);
    lock.lock();
    if(gmlSession_!=session || !gmlSnapshot_.ready())return false;
    gmlSnapshot_.error.clear();
    if(!inspected) {
        stop->instanceCount=0;stop->instancesComplete=0;stop->instanceVariablesComplete=0;
        uint32_t retained=0;
        for(uint32_t i=0;i<stop->numericSlotCount;++i)
            if(stop->numericSlots[i].scope!=GmlVariableScope::SessionInstance)stop->numericSlots[retained++]=stop->numericSlots[i];
        stop->numericSlotCount=retained;
        gmlSnapshot_.error="Instance inspection unavailable: "+inspectionError;
    }
    s.observedCodes[stop->location.codeIndex]=true;
    auto& capabilities=gmlSnapshot_.capabilities;
    capabilities.observed|=GmlCapabilityBit(GmlRunnerCapability::InstructionStops)|GmlCapabilityBit(GmlRunnerCapability::Frames);
    if(stop->reason==GmlStopReason::Step)capabilities.observed|=GmlCapabilityBit(GmlRunnerCapability::CallAwareSteps);
    if(stop->globalsComplete)capabilities.observed|=GmlCapabilityBit(GmlRunnerCapability::Globals);
    if(stop->instancesComplete)capabilities.observed|=GmlCapabilityBit(GmlRunnerCapability::Instances);
    for(uint32_t i=0;i<stop->frameCount;++i)if(stop->frames[i].localsAvailability==GmlValueAvailability::Available)
        capabilities.observed|=GmlCapabilityBit(GmlRunnerCapability::Locals);
    for(uint32_t i=0;i<stop->numericSlotCount;++i)if(stop->numericSlots[i].writable)
        capabilities.observed|=GmlCapabilityBit(GmlRunnerCapability::NumericEdits);
    gmlSnapshot_.boundBreakpoints=(uint32_t)std::count_if(s.breakpoints.begin(),s.breakpoints.end(),[&](const auto& bp){return s.observedCodes[bp.codeIndex];});
    s.stopSequence=stop->identity.stopSequence;
    gmlSnapshot_.stop=std::move(stop);gmlSnapshot_.state=GameMakerSessionState::Paused;
    gmlSnapshot_.instructionStopsVerified=true;gmlSnapshot_.status="Paused before the selected GML instruction";
    if(gmlSnapshot_.stop->reason==GmlStopReason::Error)
        gmlSnapshot_.error="GML stepping could not validate its frame transition; execution is stopped at a verified instruction.";
    ++gmlSnapshot_.revision;return true;
}
bool Debugger::resumeGameMakerOwned(GmlControlCommand command) {
    std::lock_guard lock(mtx_);
    if (gmlSession_ && gmlSession_->disablePublished &&
        (gmlSnapshot_.state==GameMakerSessionState::Inert || gmlSnapshot_.state==GameMakerSessionState::Disabling ||
         gmlSnapshot_.state==GameMakerSessionState::Failed) &&
        (command==GmlControlCommand::Continue || command==GmlControlCommand::None)) return true;
    if(!gmlSession_ || !gmlSnapshot_.stop)return false;
    auto& s=*gmlSession_;const auto& stop=*gmlSnapshot_.stop;
    if(command==GmlControlCommand::None)command=s.resumeCommand;
    if(command!=GmlControlCommand::Continue && command!=GmlControlCommand::StepInto &&
       command!=GmlControlCommand::StepOver && command!=GmlControlCommand::StepOut)return false;
    auto control=std::make_unique<GmlHelperControl>();
    control->nonce=s.nonce;control->commandSequence=++s.commandSequence;control->expectedStop=stop.identity;
    control->command=command;control->anchorLocation=stop.location;
    control->anchorFrameId=stop.frames[0].frameId;control->anchorParentFrameId=stop.frames[0].parentFrameId;
    control->anchorDepth=stop.frames[0].depth;control->breakpointCount=(uint32_t)s.breakpoints.size();
    control->selectedObjectIndex=s.selectedObject;control->selectedInstanceId=s.selectedInstance;
    std::copy(s.breakpoints.begin(),s.breakpoints.end(),control->breakpoints);
    if(!publishControl((HANDLE)hProcess_,s.mailbox,*control)) {
        gmlSnapshot_.error="Could not publish the resume command; the GML event remains paused.";return false;
    }
    s.resumeCommand=GmlControlCommand::None;s.breakpointUpdate=false;
    gmlSnapshot_.stop.reset();gmlSnapshot_.state=GameMakerSessionState::Running;
    gmlSnapshot_.status="Running GML bytecode";++gmlSnapshot_.revision;return true;
}
void Debugger::invalidateGameMakerPause() {
    std::lock_guard lock(mtx_);
    if(gmlSnapshot_.stop){gmlSnapshot_.stop.reset();++gmlSnapshot_.revision;}
    if(gmlSnapshot_.state==GameMakerSessionState::Paused)gmlSnapshot_.state=GameMakerSessionState::Running;
}
void Debugger::cleanupGameMakerOwned(bool alive) {
    std::lock_guard lock(mtx_);
    if(!gmlSession_)return;
    auto& s=*gmlSession_;const auto previousStop=gmlSnapshot_.stop;const bool heldGml=!!previousStop;gmlSnapshot_.stop.reset();
    gmlSnapshot_.capabilities.runtimeVerified=false;
    bool restored=true,releaseSession=false;
    if(alive && hProcess_) {
        const bool helperOwned=s.helperBase && std::any_of(dbgModules_.begin(),dbgModules_.end(),[&](const auto& module){
            return module.base==s.helperBase && module.size==s.helperSize && module.loadGeneration==s.helper.loadGeneration &&
                SameAttachedFileIdentity(module.fileIdentity,s.helper.fileIdentity);
        });
        if(s.mailbox && helperOwned) {
            auto control=std::make_unique<GmlHelperControl>();control->nonce=s.nonce;
            control->commandSequence=++s.commandSequence;control->command=GmlControlCommand::Disable;
            restored=publishControl((HANDLE)hProcess_,s.mailbox,*control);
            s.disablePublished=restored;
        }
        if(s.helperBase && !helperOwned)restored=false;
        const bool runnerOwned=std::any_of(dbgModules_.begin(),dbgModules_.end(),[&](const auto& module){
            return module.base==s.runner.base && module.loadGeneration==s.runner.loadGeneration &&
                SameAttachedFileIdentity(module.fileIdentity,s.runner.fileIdentity);
        });
        if(!runnerOwned) s.hooks.fill(false); // never restore bytes into a replaced mapping
        if(s.prepared.profile && runnerOwned) {
            const auto sites=hookSites(*s.prepared.profile);
            for(size_t i=0;i<sites.size();++i)if(s.hooks[i]) {
                const auto& site=sites[i];
                const uint64_t address=s.runner.base+site.rva;
                std::array<uint8_t,16> current{};
                bool ok=remoteRead(hProcess_,address,current.data(),site.byteCount);
                if(ok && std::memcmp(current.data(),site.original.data(),site.byteCount))
                    ok=replaceCode((HANDLE)hProcess_,address,
                        {s.patches[i].data(),site.byteCount},{site.original.data(),site.byteCount});
                // Even an installation that rolled its bytes back may have
                // failed to restore protection. Preserve the first old value.
                DWORD ignored=0;
                if(ok && s.originalProtection[i])ok=!!VirtualProtectEx((HANDLE)hProcess_,(LPVOID)address,
                    site.byteCount,s.originalProtection[i],&ignored);
                if(ok)ok=!!FlushInstructionCache((HANDLE)hProcess_,(LPCVOID)address,site.byteCount);
                restored=ok && restored;if(ok)s.hooks[i]=false;
            }
        }
        gmlSnapshot_.mappingRetained=s.helperBase!=0;
        gmlSnapshot_.state=restored?GameMakerSessionState::Disabling:GameMakerSessionState::Failed;
        gmlSnapshot_.status=restored?"GML stops disabled and hooks restored; draining callbacks before unload":
            "GML cleanup could not verify every owned hook restoration";
        if(!restored)gmlSnapshot_.error=gmlSnapshot_.status;
        if(!s.disablePublished && previousStop)gmlSnapshot_.stop=previousStop;
        // No waiting or target function invocation under the held event. Queue
        // an ordinary remote-thread bootstrap only after the frozen count plus
        // all recorded thread contexts prove no callback/gate/relay can return.
        if(restored && helperOwned && !s.initThread && !s.loaderThread && !s.shutdownThread) {
            const auto activeAddress=resolveMappedExport(s.helperBase,s.helperSize,"gDsGmlActiveGates");
            uint64_t active=UINT64_MAX;
            bool drained=activeAddress && remoteRead(hProcess_,activeAddress,&active,sizeof(active)) && active==0;
            for(const auto& [tid,handle]:threads_) {
                (void)tid;
                const uint64_t rip=ctxReadRip(handle);
                if(!rip || (rip>=s.helperBase && rip-s.helperBase<s.helperSize) ||
                    (rip>=s.relay && rip-s.relay<64))drained=false;
            }
            if(drained) {
                const auto shutdown=resolveMappedExport(s.helperBase,s.helperSize,"DsGmlShutdown");
                if(shutdown)s.shutdownThread=CreateRemoteThread((HANDLE)hProcess_,nullptr,0,(LPTHREAD_START_ROUTINE)shutdown,nullptr,0,nullptr);
                if(s.shutdownThread)gmlSnapshot_.status="GML callbacks drained; unloading the helper asynchronously";
                else {gmlSnapshot_.state=GameMakerSessionState::Inert;gmlSnapshot_.status="Hooks restored; safe helper unload unavailable, retaining an inert mapping";}
            } else if(quit_) {
                gmlSnapshot_.state=GameMakerSessionState::Inert;
                gmlSnapshot_.status="Hooks restored; an unproven callback remains, retaining an inert helper mapping";
            }
        } else if(restored && !s.helperBase) {
            gmlSnapshot_.state=GameMakerSessionState::Disconnected;
            gmlSnapshot_.status="GameMaker setup cancelled before loading a helper";
            if(!s.loaderThread && !s.initThread) {
                if(s.remotePath)VirtualFreeEx((HANDLE)hProcess_,(LPVOID)s.remotePath,0,MEM_RELEASE);
                releaseSession=true;gmlOwnedRanges_.clear();
            }
        }
        // A notification can be authenticated just before the native snapshot
        // enters Paused. Queue continuation there too, otherwise cancellation
        // racing that publication would strand the already-consumed event.
        if(heldGml && s.disablePublished && !quit_) {
            pendingCommand_={Cmd::Continue,0,controlEpoch_};cmdCv_.notify_all();
        }
    } else {
        gmlSnapshot_.mappingRetained=false;gmlSnapshot_.state=GameMakerSessionState::Disconnected;
        gmlSnapshot_.status="GameMaker process exited";gmlOwnedRanges_.clear();
    }
    s.disableRequested=false;++gmlSnapshot_.revision;
    if(releaseSession)gmlSession_.reset();
}
} // namespace ds
