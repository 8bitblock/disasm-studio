#include "Core/GameMakerArchive.h"
#include "gamemaker_fixture.h"
#include <cstdio>
#include <fstream>
#include <iterator>

static int failures=0;
#define CHECK(x) do { if(!(x)){std::printf("FAIL %d: %s\n",__LINE__,#x);++failures;} }while(0)
int main(int argc,char** argv) {
    auto f=gmltest::BuildArchive();auto a=ds::ParseGameMakerArchive(f.bytes.data(),f.bytes.size());
    if(!a.ok)std::printf("parse: %s\n",a.error.c_str());
    CHECK(a.ok);CHECK(a.bytecodeVersion==17);CHECK(a.gameName=="Synthetic Game");CHECK(a.code.size()==2);CHECK(a.strings.size()==8);CHECK(a.references.size()==3);CHECK(a.instructionOffsets.size()==8);
    if(a.code.size()==2){CHECK(a.code[1].parentIndex==0);CHECK(a.code[1].entryFileOffset()==f.childOffset);CHECK(a.code[0].instructionsComplete);CHECK(a.code[1].bytecodeOffset==f.rootOffset);}
    CHECK(a.variables.size()==1);CHECK(a.functions.size()==1);CHECK(a.referencesComplete);
    if(!a.functions.empty())CHECK(a.functions[0].codeIndex==1);
    CHECK(a.scripts.size()==1);CHECK(a.globalCodeIndices.size()==1);CHECK(a.objects.size()==1);
    if(!a.objects.empty()){CHECK(a.objects[0].eventsComplete);CHECK(a.objects[0].events.size()==1);CHECK(a.objects[0].events[0].codeIndex==0);}
    CHECK(a.codeAtOffset(f.childOffset)!=nullptr);CHECK(!a.codeAtOffset(0));CHECK(a.isInstructionOffset(f.callInstruction));CHECK(!a.isInstructionOffset(f.callInstruction+4));
    auto mutated=f.bytes;mutated.resize(30);CHECK(!ds::ParseGameMakerArchive(mutated.data(),mutated.size()).ok);
    mutated=f.bytes;gmltest::Set32(mutated,4,UINT32_MAX);CHECK(!ds::ParseGameMakerArchive(mutated.data(),mutated.size()).ok);
    mutated=f.bytes;gmltest::Set32(mutated,f.codeRecord+12,0x80000000);CHECK(!ds::ParseGameMakerArchive(mutated.data(),mutated.size()).ok);
    mutated=f.bytes;gmltest::Set32(mutated,f.childRecord+4,4);CHECK(!ds::ParseGameMakerArchive(mutated.data(),mutated.size()).ok);
    mutated=f.bytes;gmltest::Set32(mutated,f.childRecord+16,16);CHECK(!ds::ParseGameMakerArchive(mutated.data(),mutated.size()).ok);
    mutated=f.bytes;gmltest::Set32(mutated,f.variableRecord+12,UINT32_MAX);CHECK(!ds::ParseGameMakerArchive(mutated.data(),mutated.size()).ok);
    mutated=f.bytes;gmltest::Set32(mutated,f.variableRecord+12,2);gmltest::Set32(mutated,f.variableInstruction+4,0xa0000000);auto broken=ds::ParseGameMakerArchive(mutated.data(),mutated.size());CHECK(broken.ok);CHECK(!broken.referencesComplete);CHECK(broken.referenceAtOffset(f.variableInstruction)==nullptr);
    mutated=f.bytes;mutated[f.genOffset+1]=99;auto unknown=ds::ParseGameMakerArchive(mutated.data(),mutated.size());CHECK(unknown.ok);CHECK(!unknown.bytecodeSupported);CHECK(unknown.code.empty());
    for(int version:{15,16,17}){mutated=f.bytes;mutated[f.genOffset+1]=static_cast<uint8_t>(version);auto supported=ds::ParseGameMakerArchive(mutated.data(),mutated.size());CHECK(supported.ok && supported.bytecodeSupported);}
    // Older FUNC records point at the instruction; establish one convention for the table.
    mutated=f.bytes;gmltest::Set32(mutated,f.functionRecord+8,f.callInstruction);auto older=ds::ParseGameMakerArchive(mutated.data(),mutated.size());CHECK(older.ok && older.referencesComplete);CHECK(older.referenceAtOffset(f.callInstruction)!=nullptr);
    mutated=f.bytes;gmltest::Set32(mutated,f.variableInstruction+4,0xa0000007);auto terminal=ds::ParseGameMakerArchive(mutated.data(),mutated.size());CHECK(terminal.ok && !terminal.referencesComplete);CHECK(terminal.referenceAtOffset(f.variableInstruction)==nullptr);
    mutated=f.bytes;gmltest::Set32(mutated,f.codeRecord,1);CHECK(!ds::ParseGameMakerArchive(mutated.data(),mutated.size()).ok);
    mutated=f.bytes;gmltest::Set32(mutated,f.stringOffsets[4]-4,UINT32_MAX);CHECK(!ds::ParseGameMakerArchive(mutated.data(),mutated.size()).ok);
    mutated=f.bytes;gmltest::Set32(mutated,f.stringInstruction+4,1000);CHECK(!ds::ParseGameMakerArchive(mutated.data(),mutated.size()).ok);
    mutated=f.bytes;gmltest::Set32(mutated,f.rootOffset,0x01000000);auto unsupported=ds::ParseGameMakerArchive(mutated.data(),mutated.size());CHECK(unsupported.ok);CHECK(!unsupported.code[0].instructionsComplete);CHECK(unsupported.instructionOffsets.empty());CHECK(!unsupported.referencesComplete);
    int polls=0;auto midCancel=ds::ParseGameMakerArchive(f.bytes.data(),f.bytes.size(),[&]{return ++polls==18;});CHECK(!midCancel.ok && midCancel.cancelled);CHECK(polls==18);
    auto cancel=ds::ParseGameMakerArchive(f.bytes.data(),f.bytes.size(),[]{return true;});CHECK(!cancel.ok && cancel.cancelled);
    for(size_t n=0;n<f.bytes.size();++n)CHECK(!ds::ParseGameMakerArchive(f.bytes.data(),n).ok);
    if(argc>1){std::ifstream stream(argv[1],std::ios::binary);std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(stream)),{});auto actual=ds::ParseGameMakerArchive(bytes.data(),bytes.size());std::printf("actual ok=%d code=%zu roots=%zu vars=%zu funcs=%zu strings=%zu objects=%zu refs=%zu instructions=%zu error=%s\n",actual.ok,actual.code.size(),actual.rootCodeIndices.size(),actual.variables.size(),actual.functions.size(),actual.strings.size(),actual.objects.size(),actual.references.size(),actual.instructionOffsets.size(),actual.error.c_str());for(const auto& w:actual.warnings)std::printf("warning: %s\n",w.c_str());CHECK(actual.ok);CHECK(actual.referencesComplete);for(const auto& code:actual.code)CHECK(code.instructionsComplete);for(const auto& o:actual.objects)CHECK(o.eventsComplete);}
    std::printf("gamemaker_archive_test: %d failure(s)\n",failures);return failures?1:0;
}
