#include "GameMakerArchive.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace ds {
namespace {
constexpr uint32_t MaxRecords = 1'000'000;
constexpr uint32_t MaxInstructions = 16'000'000;
constexpr uint64_t MaxTextBytes = 64ull * 1024 * 1024;
struct ParseFailure { std::string message; };
struct Parser {
    const uint8_t* data;
    size_t size;
    const std::function<bool()>& cancel;
    GameMakerArchive out;
    std::unordered_map<uint32_t, uint32_t> stringIds;
    uint64_t textBytes = 0;
    uint64_t records = 0;
    void poll() { if (cancel && cancel()) { out.cancelled = true; throw ParseFailure{"GameMaker archive parsing cancelled"}; } }
    void require(bool yes, const char* message) { if (!yes) throw ParseFailure{message}; }
    void range(uint64_t pos, uint64_t length, uint64_t end) {
        require(pos <= end && length <= end - pos && end <= size, "GameMaker record is outside its containing chunk");
    }
    void admit(uint64_t count) {
        require(count <= MaxRecords && records <= MaxRecords * 4ull - count, "GameMaker metadata record limit exceeded");
        records += count;
    }
    uint16_t u16(uint64_t p) { range(p, 2, size); return uint16_t(data[p]) | (uint16_t(data[p+1]) << 8); }
    uint32_t u32(uint64_t p) { range(p, 4, size); return uint32_t(data[p]) | (uint32_t(data[p+1]) << 8) | (uint32_t(data[p+2]) << 16) | (uint32_t(data[p+3]) << 24); }
    int32_t i32(uint64_t p) { return static_cast<int32_t>(u32(p)); }
    bool zeroTail(uint64_t p, uint64_t end) {
        if (p > end || end - p > 15) return false;
        for (; p < end; ++p) if (data[p]) return false;
        return true;
    }
    const GameMakerChunk* chunk(const char* name) const {
        for (const auto& c : out.chunks) if (c.tag == name) return &c;
        return nullptr;
    }
    std::string name(uint32_t p, bool nullAllowed = false) {
        if (!p && nullAllowed) return {};
        auto it = stringIds.find(p);
        require(it != stringIds.end(), "GameMaker name does not point to a STRG string");
        const auto& text=out.strings[it->second].text;
        require(textBytes+text.size()<=MaxTextBytes,"GameMaker aggregate string/name storage limit exceeded");
        textBytes+=text.size();
        return text;
    }
    std::vector<uint32_t> pointers(uint64_t p, uint64_t end, uint64_t minimum = 0) {
        range(p, 4, end); const uint32_t count = u32(p); admit(count);
        range(p+4, uint64_t(count)*4, end);
        std::vector<uint32_t> result; result.reserve(count);
        for (uint32_t i=0; i<count; ++i) {
            if (!(i & 1023)) poll();
            uint32_t target = u32(p+4+uint64_t(i)*4);
            require(target >= std::max(minimum, p+4+uint64_t(count)*4) && target < end,
                    "GameMaker pointer table contains an invalid target");
            result.push_back(target);
        }
        return result;
    }
    void warning(const char* message) {
        if (out.warnings.size() < 32 && std::find(out.warnings.begin(), out.warnings.end(), message) == out.warnings.end()) out.warnings.emplace_back(message);
    }
    void parseStrings() {
        auto c = chunk("STRG"); require(c != nullptr, "GameMaker archive has no STRG chunk");
        auto ptrs = pointers(c->fileOffset, c->fileOffset+c->length);
        out.strings.reserve(ptrs.size());
        for (uint32_t i=0; i<ptrs.size(); ++i) {
            if (!(i & 255)) poll();
            const uint64_t p=ptrs[i], end=c->fileOffset+c->length;
            range(p,4,end); uint32_t n=u32(p);
            require(n <= 1024*1024 && textBytes+n <= MaxTextBytes, "GameMaker string storage limit exceeded");
            range(p+4,uint64_t(n)+1,end);
            require(data[p+4+n] == 0, "GameMaker string lacks its declared terminator");
            textBytes += n;
            out.strings.push_back({i,p+4,std::string(reinterpret_cast<const char*>(data+p+4),n)});
            require(stringIds.emplace(static_cast<uint32_t>(p+4),i).second, "GameMaker STRG contains duplicate string pointers");
        }
    }
    void parseCode() {
        auto c=chunk("CODE"); if (!c || !c->length) return;
        auto ptrs=pointers(c->fileOffset,c->fileOffset+c->length);
        std::unordered_map<uint64_t,uint32_t> roots;
        std::unordered_set<uint32_t> headers;
        std::vector<std::pair<uint64_t,uint64_t>> headerRanges;
        for (uint32_t p:ptrs) {
            range(p,20,c->fileOffset+c->length);
            require(headers.insert(p).second,"GameMaker CODE has duplicate entry record pointers");
            headerRanges.emplace_back(p,uint64_t(p)+20);
        }
        std::sort(headerRanges.begin(),headerRanges.end());
        for (size_t i=1;i<headerRanges.size();++i) require(headerRanges[i-1].second<=headerRanges[i].first,"GameMaker CODE records overlap");
        for (uint32_t i=0;i<ptrs.size();++i) {
            if (!(i & 255)) poll();
            uint64_t p=ptrs[i]; GameMakerCode code;
            code.index=i; code.recordOffset=p; code.name=name(u32(p)); code.bytecodeLength=u32(p+4);
            code.localsCount=u16(p+8); code.argumentsCount=u16(p+10)&0x7fff;
            code.localFlag=(u16(p+10)&0x8000)!=0;
            const int64_t address=static_cast<int64_t>(p+12)+i32(p+12);
            require(address>=0,"GameMaker CODE relative bytecode pointer underflows");
            code.bytecodeOffset=static_cast<uint64_t>(address); code.entryOffset=u32(p+16);
            require((code.bytecodeOffset&3)==0 && !(code.bytecodeLength&3) && !(code.entryOffset&3),"GameMaker bytecode must be word aligned");
            require(code.bytecodeOffset>=c->fileOffset+4+ptrs.size()*4,"GameMaker bytecode overlaps CODE pointer table");
            range(code.bytecodeOffset,code.bytecodeLength,c->fileOffset+c->length);
            require(code.entryOffset<=code.bytecodeLength && (!code.bytecodeLength || code.entryOffset<code.bytecodeLength),"GameMaker child entry is outside its bytecode body");
            if (code.bytecodeLength) {
                auto h=std::lower_bound(headerRanges.begin(),headerRanges.end(),code.bytecodeOffset,
                    [](const auto& a,uint64_t b){return a.second<=b;});
                require(h==headerRanges.end() || h->first>=code.bytecodeOffset+code.bytecodeLength,"GameMaker bytecode overlaps CODE metadata");
                auto [it,inserted]=roots.emplace(code.bytecodeOffset,i);
                if (!inserted) {
                    code.parentIndex=it->second;
                    require(code.bytecodeLength==out.code[it->second].bytecodeLength,"GameMaker shared bytecode lengths disagree");
                } else {
                    require(code.entryOffset==0,"GameMaker root CODE entry has nonzero entry offset");
                    out.rootCodeIndices.push_back(i);
                }
            }
            out.code.push_back(std::move(code));
        }
        std::sort(out.rootCodeIndices.begin(),out.rootCodeIndices.end(),[&](uint32_t a,uint32_t b){return out.code[a].bytecodeOffset<out.code[b].bytecodeOffset;});
        uint64_t previousEnd=0;
        for (uint32_t i:out.rootCodeIndices) {
            auto& code=out.code[i]; require(code.bytecodeOffset>=previousEnd,"GameMaker bytecode bodies partially overlap");
            previousEnd=code.bytecodeOffset+code.bytecodeLength;
            for (uint32_t offset=0;offset<code.bytecodeLength;) {
                if (!(out.instructionOffsets.size() & 4095)) poll();
                require(out.instructionOffsets.size()<MaxInstructions,"GameMaker instruction index limit exceeded");
                uint32_t w=u32(code.bytecodeOffset+offset),len=GmlEncodedInstructionLength(w,out.bytecodeVersion);
                if (!len || len>code.bytecodeLength-offset) { warning("Some CODE bodies contain unsupported or truncated instructions; only validated instruction prefixes are indexed"); break; }
                out.instructionOffsets.push_back(code.bytecodeOffset+offset);
                if ((w>>24)>=0xc0 && (w>>24)<=0xc3 && ((w>>16)&255)==6) {
                    uint32_t id=u32(code.bytecodeOffset+offset+4);
                    require(id<out.strings.size(),"GameMaker push.s has an invalid string index");
                    out.references.push_back({code.bytecodeOffset+offset,GmlReferenceKind::String,id,0});
                }
                offset+=len; code.decodedLength=offset;
            }
            code.instructionsComplete=code.decodedLength==code.bytecodeLength;
        }
        for (auto& code:out.code) {
            if (code.parentIndex!=GmlNoIndex) {
                code.instructionsComplete=out.code[code.parentIndex].instructionsComplete;
                code.decodedLength=out.code[code.parentIndex].decodedLength;
            }
            if (code.bytecodeLength && code.entryOffset<code.decodedLength)
                require(out.isInstructionOffset(code.entryFileOffset()),"GameMaker child entry points inside an instruction operand");
        }
    }
    void parseVariables() {
        auto c=chunk("VARI"); if (!c || !c->length) return;
        range(c->fileOffset,12,c->fileOffset+c->length);
        uint64_t p=c->fileOffset+12,end=c->fileOffset+c->length;
        uint32_t count=static_cast<uint32_t>((end-p)/20); admit(count);
        out.variables.reserve(count);
        for (uint32_t i=0;i<count;++i,p+=20) {
            if (!(i&255)) poll();
            GameMakerVariable v; v.index=i; v.recordOffset=p; v.name=name(u32(p));
            v.instanceType=i32(p+4); v.variableId=i32(p+8); v.occurrences=u32(p+12); v.firstOccurrence=u32(p+16);
            require(v.occurrences<=MaxInstructions,"GameMaker variable occurrence count exceeds limit");
            require(v.occurrences || v.firstOccurrence==UINT32_MAX,"GameMaker unused variable has a live reference pointer");
            out.variables.push_back(std::move(v));
        }
        require(zeroTail(p,end),"GameMaker VARI has an incomplete trailing record");
    }
    void parseFunctions() {
        auto c=chunk("FUNC"); if (!c || !c->length) return;
        uint64_t p=c->fileOffset,end=p+c->length; range(p,4,end); uint32_t count=u32(p); p+=4; admit(count); range(p,uint64_t(count)*12,end);
        for (uint32_t i=0;i<count;++i,p+=12) {
            if (!(i&255)) poll();
            GameMakerFunction f; f.index=i; f.recordOffset=p; f.name=name(u32(p)); f.occurrences=u32(p+4); f.firstOccurrence=u32(p+8);
            require(f.occurrences<=MaxInstructions,"GameMaker function occurrence count exceeds limit");
            require(f.occurrences || f.firstOccurrence==UINT32_MAX,"GameMaker unused function has a live reference pointer");
            out.functions.push_back(std::move(f));
        }
        if (zeroTail(p,end)) return; // GM 2024.8 removed CodeLocals; chunk alignment remains.
        range(p,4,end); uint32_t locals=u32(p); p+=4; admit(locals);
        for (uint32_t i=0;i<locals;++i) {
            poll(); range(p,8,end); GameMakerCodeLocals record;
            uint32_t countLocal=u32(p); record.codeName=name(u32(p+4)); p+=8; admit(countLocal); range(p,uint64_t(countLocal)*8,end);
            for (uint32_t j=0;j<countLocal;++j,p+=8) record.locals.push_back({u32(p),name(u32(p+4))});
            out.codeLocals.push_back(std::move(record));
        }
        require(zeroTail(p,end),"GameMaker FUNC has an incomplete trailing record");
    }
    bool chain(uint32_t first,uint32_t count,GmlReferenceKind kind,uint32_t index,bool commit) {
        uint64_t p=first;
        std::vector<GameMakerReference> refs;
        if (commit) refs.reserve(count);
        for (uint32_t i=0;i<count;++i) {
            if (!(i&4095)) poll();
            const auto* body=out.codeAtOffset(p);
            if (!body || !out.isInstructionOffset(p) || p+8>body->bytecodeOffset+body->bytecodeLength) return false;
            uint32_t word=u32(p); uint8_t op=uint8_t(word>>24),type=uint8_t(word>>16)&15;
            const bool push=op>=0xc0 && op<=0xc3;
            bool matches=kind==GmlReferenceKind::Variable ? ((push && (type==5 || type==2)) || (op==0x45 && type!=15))
                : (op==0xd9 || (push && type==2) || (op==0xff && type==2 && static_cast<int16_t>(word)==-11));
            if (!matches) return false;
            uint32_t ref=u32(p+4);
            if (commit) refs.push_back({p,kind,index,static_cast<uint8_t>((ref>>24)&0xf8)});
            if (i+1<count) { uint32_t delta=ref&0x07ffffff; if (!delta || (delta&3)) return false; p+=delta; }
            else {
                // The final operand carries the symbol's STRG index, not another link.
                uint32_t stringId=ref&0xffffff;
                const auto& expected=kind==GmlReferenceKind::Variable?out.variables[index].name:out.functions[index].name;
                if(stringId>=out.strings.size() || out.strings[stringId].text!=expected)return false;
            }
        }
        if (commit) out.references.insert(out.references.end(),refs.begin(),refs.end());
        return true;
    }
    void parseReferences() {
        uint64_t total=out.references.size();
        for (auto& v:out.variables) { total+=v.occurrences; require(total<=MaxInstructions,"GameMaker aggregate reference limit exceeded"); v.referencesComplete=chain(v.firstOccurrence,v.occurrences,GmlReferenceKind::Variable,v.index,true); if (!v.referencesComplete) out.referencesComplete=false; }
        // The function pointer shifted from instruction to operand in GMS 2.3.
        // Prove one consistent convention across the entire table; never choose per-reference guesses.
        bool direct=true,operand=true; bool any=false;
        for (const auto& f:out.functions) {
            total+=f.occurrences; require(total<=MaxInstructions,"GameMaker aggregate reference limit exceeded");
            if (!f.occurrences) continue; any=true;
            if (direct) direct=chain(f.firstOccurrence,f.occurrences,GmlReferenceKind::Function,f.index,false);
            if (operand) operand=f.firstOccurrence>=4 && chain(f.firstOccurrence-4,f.occurrences,GmlReferenceKind::Function,f.index,false);
        }
        for (auto& f:out.functions) {
            if (!f.occurrences) f.referencesComplete=true;
            else if (direct!=operand) f.referencesComplete=chain(f.firstOccurrence-(operand?4:0),f.occurrences,GmlReferenceKind::Function,f.index,true);
            else out.referencesComplete=false;
        }
        if (any && direct==operand) warning("FUNC reference addressing is ambiguous or invalid; function references remain unresolved");
        if (!out.referencesComplete) warning("Some variable/function reference chains could not be validated completely");
        std::sort(out.references.begin(),out.references.end(),[](const auto& a,const auto& b){return a.instructionOffset<b.instructionOffset;});
        for (size_t i=1;i<out.references.size();++i)
            require(out.references[i-1].instructionOffset!=out.references[i].instructionOffset,"GameMaker instruction belongs to conflicting symbol reference chains");
    }
    void parseScripts() {
        if (auto c=chunk("SCPT");c && c->length) {
            for (uint32_t p:pointers(c->fileOffset,c->fileOffset+c->length)) {
                poll(); range(p,8,c->fileOffset+c->length); GameMakerScript s; s.name=name(u32(p));
                uint32_t id=u32(p+4); s.constructor=id!=UINT32_MAX && (id&0x80000000)!=0;
                s.codeIndex=id==UINT32_MAX?GmlNoIndex:id&0x7fffffff;
                require(s.codeIndex==GmlNoIndex || s.codeIndex<out.code.size(),"GameMaker script references an invalid CODE entry");
                out.scripts.push_back(std::move(s));
            }
        }
        if (auto c=chunk("GLOB");c && c->length) {
            uint64_t p=c->fileOffset,end=p+c->length;range(p,4,end);uint32_t n=u32(p);admit(n);range(p+4,uint64_t(n)*4,end);
            for (uint32_t i=0;i<n;++i) { uint32_t id=u32(p+4+uint64_t(i)*4);require(id<out.code.size(),"GameMaker global initializer references invalid CODE");out.globalCodeIndices.push_back(id); }
            require(zeroTail(p+4+uint64_t(n)*4,end),"GameMaker GLOB has trailing data");
        }
        std::unordered_map<std::string,uint32_t> targets;
        auto add=[&](const std::string& n,uint32_t id){if(id==GmlNoIndex)return;auto [it,inserted]=targets.emplace(n,id);if(!inserted && it->second!=id)it->second=GmlNoIndex;};
        for (const auto& c:out.code) add(c.name,c.index);
        for (const auto& s:out.scripts) add(s.name,s.codeIndex);
        for (auto& f:out.functions) {auto i=targets.find(f.name);if(i!=targets.end()) f.codeIndex=i->second;}
    }
    void parseObjects() {
        auto c=chunk("OBJT"); if (!c || !c->length)return;
        auto ptrs=pointers(c->fileOffset,c->fileOffset+c->length);
        auto sorted=ptrs;std::sort(sorted.begin(),sorted.end());
        require(std::adjacent_find(sorted.begin(),sorted.end())==sorted.end(),"GameMaker OBJT contains duplicate object pointers");
        for (uint32_t i=0;i<ptrs.size();++i) {
            poll();uint64_t p=ptrs[i]; auto next=std::upper_bound(sorted.begin(),sorted.end(),p); uint64_t end=next==sorted.end()?c->fileOffset+c->length:*next;
            range(p,80,end);GameMakerObject obj;obj.index=i;obj.recordOffset=p;obj.name=name(u32(p));
            uint64_t eventList=0;unsigned candidates=0; bool managed=false;
            for (unsigned shift:{0u,4u}) {
                if (p+80+shift+4>end) continue;
                uint32_t vertices=u32(p+64+shift); if (vertices>65536)continue;
                uint64_t list=p+80+shift+uint64_t(vertices)*8;
                if(list+4>end)continue;uint32_t kinds=u32(list);if(kinds<12 || kinds>16 || uint64_t(kinds)*4>end-list-4)continue;
                bool valid=true;uint32_t prev=0;
                for(uint32_t j=0;j<kinds;++j){uint32_t target=u32(list+4+uint64_t(j)*4);if(target<list+4+uint64_t(kinds)*4 || target+uint64_t(4)>end || (j && target<=prev)){valid=false;break;}prev=target;}
                if(valid){++candidates;eventList=list;managed=shift!=0;}
            }
            if(candidates!=1){warning("Some OBJT event layouts are unsupported or ambiguous; their event associations are unavailable");out.objects.push_back(std::move(obj));continue;}
            obj.parentIndex=i32(p+(managed?28:24));
            require(obj.parentIndex<0 || uint32_t(obj.parentIndex)<ptrs.size(),"GameMaker object parent index is invalid");
            auto types=pointers(eventList,end);
            for(uint32_t type=0;type<types.size();++type) {
                auto events=pointers(types[type],end);
                for(uint32_t ev:events) {
                    range(ev,8,end);uint32_t subtype=u32(ev);
                    auto actions=pointers(uint64_t(ev)+4,end);
                    for(uint32_t action:actions) {
                        range(action,56,end);GameMakerEvent event;event.type=type;event.subtype=subtype;event.actionName=name(u32(uint64_t(action)+28),true);event.codeIndex=u32(uint64_t(action)+32);
                        require(event.codeIndex==GmlNoIndex || event.codeIndex<out.code.size(),"GameMaker event action references invalid CODE");
                        obj.events.push_back(std::move(event));
                    }
                }
            }
            obj.eventsComplete=true;out.objects.push_back(std::move(obj));
        }
    }
    GameMakerArchive run() {
        try {
            poll();require(IsGameMakerArchiveImage(data,size),"Not a GameMaker FORM archive");
            out.declaredFileSize=uint64_t(u32(4))+8;require(out.declaredFileSize<=size,"GameMaker FORM extent exceeds file size");
            uint64_t p=8;std::unordered_set<std::string> tags;
            while(p<out.declaredFileSize) {
                poll();range(p,8,out.declaredFileSize);require(out.chunks.size()<4096,"GameMaker chunk limit exceeded");
                std::string tag(reinterpret_cast<const char*>(data+p),4);
                for(char ch:tag)require(ch>='0' && ch<='Z',"GameMaker chunk tag is invalid");
                uint32_t n=u32(p+4);range(p+8,n,out.declaredFileSize);
                require(tags.insert(tag).second,"GameMaker archive contains a duplicate chunk");
                out.chunks.push_back({tag,p+8,n});p+=8+uint64_t(n);
            }
            auto gen=chunk("GEN8");require(gen!=nullptr,"GameMaker archive has no GEN8 chunk");range(gen->fileOffset,60,gen->fileOffset+gen->length);
            out.bytecodeVersion=data[gen->fileOffset+1];out.versionMajor=u32(gen->fileOffset+44);out.versionMinor=u32(gen->fileOffset+48);out.versionRelease=u32(gen->fileOffset+52);out.versionBuild=u32(gen->fileOffset+56);
            parseStrings();out.gameName=name(u32(gen->fileOffset+40),true);
            out.bytecodeSupported=out.bytecodeVersion>=15 && out.bytecodeVersion<=17;
            if(!out.bytecodeSupported){warning("Unsupported GameMaker bytecode version; code is not decoded as native instructions");out.ok=true;return std::move(out);}
            parseCode();parseVariables();parseFunctions();parseReferences();parseScripts();parseObjects();poll();out.ok=true;
        } catch(const ParseFailure& e) {out.error=e.message;out.ok=false;}
          catch(const std::bad_alloc&) {out.error="GameMaker parser allocation failed within admitted limits";out.ok=false;}
          catch(const std::length_error&) {out.error="GameMaker metadata allocation length is invalid";out.ok=false;}
        return std::move(out);
    }
};
}
bool IsGameMakerArchiveImage(const uint8_t* data,size_t size) {return data && size>=8 && std::memcmp(data,"FORM",4)==0;}
GameMakerArchive ParseGameMakerArchive(const uint8_t* data,size_t size,const std::function<bool()>& cancelled) {return Parser{data,size,cancelled}.run();}
const GameMakerCode* GameMakerArchive::codeAtOffset(uint64_t offset) const {
    auto it=std::upper_bound(rootCodeIndices.begin(),rootCodeIndices.end(),offset,[&](uint64_t a,uint32_t b){return a<code[b].bytecodeOffset;});
    if(it==rootCodeIndices.begin())return nullptr;const auto& c=code[*--it];return offset-c.bytecodeOffset<c.bytecodeLength?&c:nullptr;
}
const GameMakerReference* GameMakerArchive::referenceAtOffset(uint64_t offset) const {
    auto i=std::lower_bound(references.begin(),references.end(),offset,[](const auto& a,uint64_t b){return a.instructionOffset<b;});
    return i!=references.end() && i->instructionOffset==offset?&*i:nullptr;
}
bool GameMakerArchive::isInstructionOffset(uint64_t offset) const {return std::binary_search(instructionOffsets.begin(),instructionOffsets.end(),offset);}
uint32_t GmlEncodedInstructionLength(uint32_t w,uint8_t version) {
    if(version<15 || version>17)return 0;
    uint8_t op=uint8_t(w>>24),type=uint8_t(w>>16)&15,second=uint8_t(w>>20)&15;
    if((op>=0xb6 && op<=0xb8) || op==0xba || op==0xbb)return 4;
    auto validType=[](uint8_t t){return t<=6 || t==15;};
    if(!validType(type) || !validType(second))return 0;
    if(op>=7 && op<=0x15)return 4;
    if(op==0x86 || op==0x99 || (op>=0x9c && op<=0x9e))return second==0?4:0;
    if(op==0x45)return type==15?4:8;
    if(op==0xd9)return second==0?8:0;
    if(op==0xff)return second==0?(type==2?8:4):0;
    if(op==0x84 || (op>=0xc0 && op<=0xc3)) {
        if((w&0x00f00000)!=0)return 0;
        if(type==0 || type==3)return 12;
        if(type==2 || type==5 || type==6)return 8;
        if(type==15)return 4;
    }
    return 0;
}
const char* GmlScopeName(int32_t type) {
    switch(type){case -1:return "self";case -2:return "other";case -3:return "all";case -4:return "noone";case -5:return "global";case -6:return "builtin";case -7:return "local";case -9:return "stacktop";case -15:return "argument";case -16:return "static";default:return "instance";}
}
const char* GmlEventName(uint32_t t) {
    static const char* names[]={"Create","Destroy","Alarm","Step","Collision","Keyboard","Mouse","Other","Draw","KeyPress","KeyRelease","Trigger","CleanUp","Gesture","PreCreate"};
    return t<sizeof(names)/sizeof(*names)?names[t]:"Unknown event";
}
} // namespace ds
