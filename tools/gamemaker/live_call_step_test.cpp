#define main base_acceptance_main
#include "live_debugger_test.cpp"
#undef main
#include "Disasm/GmlDisassembler.h"
#include <set>
#include <tuple>
int main(int argc,char** argv){
    if(argc!=2){std::puts("Usage: live_call_step_test.exe <explicit owned Nubby PID>");return 2;}
    const DWORD pid=strtoul(argv[1],nullptr,10);
    const std::string path="C:\\Program Files (x86)\\Steam\\steamapps\\common\\Nubby's Number Factory\\data.win";
    BinaryFile binary;if(!binary.load(path))return 1;
    auto archive=binary.gameMakerArchive();if(!archive)return 1;
    const auto found=std::find_if(archive->code.begin(),archive->code.end(),[](const auto& c){return c.name=="gml_Script___scribble_tick";});
    if(found==archive->code.end())return 1;
    std::vector<GmlSavedBreakpoint> bps={{{binary.contentHash(),found->index,found->entryOffset,found->parentIndex},true}};
    Debugger debugger;std::string error;if(!debugger.attach(pid,error))return 1;
    for(int i=0;i<500 && debugger.snapshot().modules.empty();++i)Sleep(10);
    if(!debugger.connectGameMaker(archive,path,binary.contentHash(),bps,error)){debugger.detach();return 1;}
    auto stop=waitStop(debugger,0,45000);if(!stop.stop){debugger.detach();return 1;}
    CHECK(debugger.setGameMakerBreakpoints(binary.contentHash(),{},error));
    GmlDisassembler decoder;decoder.attachArchive(archive);
    bool entered=false,over=false,loop=false;uint32_t instructionCount=0,calls=0;
    std::set<std::tuple<uint32_t,uint32_t,uint64_t>> visited;
    for(;instructionCount<2048 && !(entered&&over&&loop);++instructionCount){
        const auto location=stop.stop->location;const auto frame=stop.stop->frames[0].frameId;
        const auto& code=archive->code[location.codeIndex];
        const auto offset=code.bytecodeOffset+location.byteOffset;
        Instruction instruction;
        if(!decoder.decodeOne(binary.bytes().data()+offset,binary.bytes().size()-offset,offset,instruction)){CHECK(false);break;}
        if(!visited.insert({location.codeIndex,location.byteOffset,frame}).second){
            if(!loop)std::printf("PROVED LOOP %s +%x frame=%llu\n",code.name.c_str(),location.byteOffset,(unsigned long long)frame);
            loop=true;
        }
        const bool knownGmlCall=instruction.isCall && instruction.branchTargetValid;
        const auto command=knownGmlCall && entered && !over?GmlControlCommand::StepOver:GmlControlCommand::StepInto;
        if(instruction.isCall){++calls;std::printf("CALL %s +%x %s %s command=%u\n",code.name.c_str(),location.byteOffset,
            instruction.mnemonic.c_str(),instruction.operands.c_str(),unsigned(command));}
        if(!doStep(debugger,stop,command)){CHECK(false);break;}
        if(knownGmlCall && command==GmlControlCommand::StepOver){
            CHECK(stop.stop->frames[0].frameId==frame);CHECK(stop.stop->location.codeIndex==location.codeIndex);
            CHECK(stop.stop->location.byteOffset==location.byteOffset+instruction.length);
            over=true;std::printf("PROVED OVER GML CALL %s returned to +%x original frame=%llu\n",instruction.operands.c_str(),
                stop.stop->location.byteOffset,(unsigned long long)frame);
        }else if(!entered && instruction.isCall && stop.stop->frames[0].frameId!=frame && stop.stop->frames[0].parentFrameId==frame){
            const auto child=stop.stop->frames[0].frameId;
            std::printf("PROVED INTO GML CALL %s caller=%llu child=%llu\n",instruction.operands.c_str(),(unsigned long long)frame,(unsigned long long)child);
            CHECK(doStep(debugger,stop,GmlControlCommand::StepOut));
            CHECK(stop.stop->frames[0].frameId==frame);CHECK(stop.stop->location.codeIndex==location.codeIndex);
            CHECK(stop.stop->location.byteOffset==location.byteOffset+instruction.length);
            entered=true;
        }
    }
    for(unsigned attempt=0;attempt<2 && (!over || !entered);++attempt){
        // The scene may spend the entire bounded trace in peg/particle events.
        // Arm exact archive call sites for UI GML scripts and let it reach one.
        std::vector<GmlSavedBreakpoint> callSites;
        for(const auto& ref:archive->references){
            if(ref.kind!=GmlReferenceKind::Function || ref.symbolIndex>=archive->functions.size())continue;
            const auto& function=archive->functions[ref.symbolIndex];
            if(function.name!="gml_Script_scr_Text" && function.name!="gml_Script_scr_LocalEqualFont")continue;
            Instruction instruction;
            if(!decoder.decodeOne(binary.bytes().data()+ref.instructionOffset,binary.bytes().size()-ref.instructionOffset,ref.instructionOffset,instruction) || !instruction.isCall || !instruction.branchTargetValid)continue;
            const auto* code=archive->codeAtOffset(ref.instructionOffset);if(!code)continue;
            if(code->parentIndex!=GmlNoIndex)code=&archive->code[code->parentIndex];
            callSites.push_back({{binary.contentHash(),code->index,uint32_t(ref.instructionOffset-code->bytecodeOffset),code->parentIndex},true});
            if(callSites.size()==kGmlMaxBreakpoints)break;
        }
        CHECK(!callSites.empty());
        CHECK(debugger.setGameMakerBreakpoints(binary.contentHash(),callSites,error));
        const auto previous=stop.stop->identity.stopSequence;
        CHECK(debugger.gameMakerCommand(GmlControlCommand::Continue,stop.stop->identity,error));
        stop=waitStop(debugger,previous,45000);CHECK(stop.stop);
        if(stop.stop){
            CHECK(debugger.setGameMakerBreakpoints(binary.contentHash(),{},error));
            const auto location=stop.stop->location;const auto frame=stop.stop->frames[0].frameId;
            const auto offset=archive->code[location.codeIndex].bytecodeOffset+location.byteOffset;
            Instruction instruction;CHECK(decoder.decodeOne(binary.bytes().data()+offset,binary.bytes().size()-offset,offset,instruction));
            CHECK(instruction.isCall && instruction.branchTargetValid);
            if(!entered){
                if(!doStep(debugger,stop,GmlControlCommand::StepInto)){CHECK(false);break;}
                entered=stop.stop->frames[0].frameId!=frame && stop.stop->frames[0].parentFrameId==frame;
                CHECK(entered);
                std::printf("PROVED INTO ARMED GML CALL %s caller=%llu child=%llu\n",instruction.operands.c_str(),(unsigned long long)frame,(unsigned long long)stop.stop->frames[0].frameId);
                if(!doStep(debugger,stop,GmlControlCommand::StepOut)){CHECK(false);break;}
            }else{
                if(!doStep(debugger,stop,GmlControlCommand::StepOver)){CHECK(false);break;}
                over=true;std::printf("PROVED OVER ARMED GML CALL %s caller=%llu continuation=%x\n",instruction.operands.c_str(),(unsigned long long)frame,stop.stop->location.byteOffset);
            }
            CHECK(stop.stop->frames[0].frameId==frame && stop.stop->location.codeIndex==location.codeIndex && stop.stop->location.byteOffset==location.byteOffset+instruction.length);
        }
    }
    CHECK(entered);CHECK(over);
    if(!stop.stop){debugger.detach();return 1;}
    // Leave nested calls first, then test the top-level event case: there is no
    // GML caller, so Out stops at the next complete chain without this frame.
    for(uint32_t i=0;i<kGmlMaxFrames && stop.stop->frames[0].depth;++i)
        if(!doStep(debugger,stop,GmlControlCommand::StepOut)){CHECK(false);debugger.detach();return 1;}
    const auto rootFrame=stop.stop->frames[0].frameId;
    CHECK(stop.stop->frames[0].depth==0);
    if(!doStep(debugger,stop,GmlControlCommand::StepOut)){CHECK(false);debugger.detach();return 1;}
    CHECK(stop.stop->framesComplete);
    for(uint32_t i=0;i<stop.stop->frameCount;++i)CHECK(stop.stop->frames[i].frameId!=rootFrame);
    std::printf("PROVED OUT TOP-LEVEL EVENT frame=%llu next=%llu\n",(unsigned long long)rootFrame,(unsigned long long)stop.stop->frames[0].frameId);
    // The live scene controls whether any loop body executes. Keep this
    // observation distinct from the deterministic same-PC stepping invariant.
    GmlExecutionPoint repeated{stop.stop->identity,stop.stop->location,stop.stop->frames[0].frameId,
        0,100,0,true,{}};
    GmlStepPlan repeatedPlan;
    CHECK(MakeGmlStepPlan(GmlControlCommand::StepInto,repeated,repeatedPlan));
    CHECK(EvaluateGmlStep(repeatedPlan,repeated)==GmlStepDecision::Continue);
    repeated.progressSequence++;
    CHECK(EvaluateGmlStep(repeatedPlan,repeated)==GmlStepDecision::Stop);
    if(!loop)std::puts("Live scene contained no repeated instruction/frame in the sample; same-PC step semantics passed the model check.");
    std::printf("TRACE instructions=%u calls=%u entered=%u over=%u loop=%u\n",instructionCount,calls,entered,over,loop);
    debugger.disconnectGameMaker();
    for(int i=0;i<3000;++i){auto s=debugger.gameMakerSnapshot();if(s.state==GameMakerSessionState::Disconnected || s.state==GameMakerSessionState::Failed || s.state==GameMakerSessionState::Inert)break;Sleep(10);}
    CHECK(debugger.gameMakerSnapshot().state==GameMakerSessionState::Disconnected);
    debugger.detach();std::printf("live_call_step_test: %s (%d failures)\n",failures?"FAILED":"PASSED",failures);return failures?1:0;
}
