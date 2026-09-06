#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace gmltest {
struct Fixture {
    std::vector<uint8_t> bytes;
    uint32_t rootOffset=0,childOffset=0,variableInstruction=0,callInstruction=0,stringInstruction=0;
    uint32_t codeRecord=0,childRecord=0,genOffset=0,variableRecord=0,functionRecord=0,rootLength=44;
    std::vector<uint32_t> stringOffsets;
};
inline void Set32(std::vector<uint8_t>& b,uint32_t at,uint32_t n) {for(unsigned i=0;i<4;++i)b[at+i]=uint8_t(n>>(8*i));}
inline uint32_t Append32(std::vector<uint8_t>& b,uint32_t n) {uint32_t at=uint32_t(b.size());b.resize(b.size()+4);Set32(b,at,n);return at;}
inline Fixture BuildArchive() {
    Fixture f;auto& b=f.bytes;b={'F','O','R','M',0,0,0,0};
    auto chunk=[&](const char* tag){uint32_t p=uint32_t(b.size());b.insert(b.end(),tag,tag+4);Append32(b,0);return p;};
    auto end=[&](uint32_t p){while(b.size()%4)b.push_back(0);Set32(b,p+4,uint32_t(b.size())-p-8);};
    std::vector<std::pair<uint32_t,uint32_t>> names;
    uint32_t c=chunk("GEN8");f.genOffset=uint32_t(b.size());b.resize(b.size()+60);b[f.genOffset+1]=17;Set32(b,f.genOffset+44,2);names.push_back({f.genOffset+40,5});end(c);
    c=chunk("CODE");Append32(b,2);uint32_t pointers=Append32(b,0);Append32(b,0);
    f.rootOffset=uint32_t(b.size());f.childOffset=f.rootOffset+4;
    Append32(b,0xb6000003);Append32(b,0x840f0007);Append32(b,0x9c050000);
    f.stringInstruction=Append32(b,0xc0060000);Append32(b,4);Append32(b,0x9e050000);
    f.variableInstruction=Append32(b,0xc005ffff);Append32(b,0xa0000002);
    f.callInstruction=Append32(b,0xd9020000);Append32(b,3);Append32(b,0x9c050000);
    f.codeRecord=uint32_t(b.size());names.push_back({Append32(b,0),0});Append32(b,f.rootLength);Append32(b,0x80000000);uint32_t rel=Append32(b,0);Set32(b,rel,f.rootOffset-rel);Append32(b,0);
    f.childRecord=uint32_t(b.size());names.push_back({Append32(b,0),1});Append32(b,f.rootLength);Append32(b,0);rel=Append32(b,0);Set32(b,rel,f.rootOffset-rel);Append32(b,4);
    Set32(b,pointers,f.codeRecord);Set32(b,pointers+4,f.childRecord);end(c);
    c=chunk("VARI");Append32(b,1);Append32(b,1);Append32(b,0);f.variableRecord=uint32_t(b.size());names.push_back({Append32(b,0),2});Append32(b,UINT32_MAX);Append32(b,0);Append32(b,1);Append32(b,f.variableInstruction);end(c);
    c=chunk("FUNC");Append32(b,1);f.functionRecord=uint32_t(b.size());names.push_back({Append32(b,0),3});Append32(b,1);Append32(b,f.callInstruction+4);end(c);
    c=chunk("SCPT");Append32(b,1);uint32_t script=Append32(b,0);Set32(b,script,uint32_t(b.size()));names.push_back({Append32(b,0),3});Append32(b,1);end(c);
    c=chunk("GLOB");Append32(b,1);Append32(b,0);end(c);
    c=chunk("OBJT");Append32(b,1);uint32_t objPtr=Append32(b,0);uint32_t obj=uint32_t(b.size());Set32(b,objPtr,obj);b.resize(b.size()+84);names.push_back({obj,6});Set32(b,obj+8,1);Set32(b,obj+12,1);Set32(b,obj+28,UINT32_MAX);Set32(b,obj+76,1);
    Append32(b,15);uint32_t events=uint32_t(b.size());b.resize(b.size()+60);
    for(uint32_t i=0;i<15;++i){Set32(b,events+i*4,uint32_t(b.size()));Append32(b,i==0?1:0);if(i==0){uint32_t ptr=Append32(b,0);Set32(b,ptr,uint32_t(b.size()));Append32(b,0);Append32(b,1);uint32_t actionPtr=Append32(b,0);uint32_t action=uint32_t(b.size());Set32(b,actionPtr,action);b.resize(b.size()+56);names.push_back({action+28,7});Set32(b,action+32,0);}}
    end(c);
    c=chunk("STRG");std::vector<std::string> strings={"gml_GlobalScript_test","gml_Script_scr_GiveMoney","money","scr_GiveMoney","hello GML","Synthetic Game","objPlayer","create"};Append32(b,uint32_t(strings.size()));uint32_t strPtrs=uint32_t(b.size());b.resize(b.size()+strings.size()*4);
    for(uint32_t i=0;i<strings.size();++i){while(b.size()%4)b.push_back(0);Set32(b,strPtrs+i*4,uint32_t(b.size()));Append32(b,uint32_t(strings[i].size()));f.stringOffsets.push_back(uint32_t(b.size()));b.insert(b.end(),strings[i].begin(),strings[i].end());b.push_back(0);}
    end(c);for(auto [pos,index]:names)Set32(b,pos,f.stringOffsets[index]);Set32(b,4,uint32_t(b.size())-8);return f;
}
}
