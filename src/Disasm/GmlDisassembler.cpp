#include "GmlDisassembler.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>

namespace ds {
namespace {
uint32_t word(const uint8_t* p) { return uint32_t(p[0]) | (uint32_t(p[1])<<8) | (uint32_t(p[2])<<16) | (uint32_t(p[3])<<24); }
uint64_t qword(const uint8_t* p) {return uint64_t(word(p)) | (uint64_t(word(p+4))<<32);}
std::string hex(uint64_t v) {char b[32];std::snprintf(b,sizeof(b),"0x%llX",static_cast<unsigned long long>(v));return b;}
std::string bytes(const uint8_t* p,size_t n) {
    static const char h[]="0123456789ABCDEF";std::string s;s.reserve(n*3);
    for(size_t i=0;i<n;++i){if(i)s+=' ';s+=h[p[i]>>4];s+=h[p[i]&15];}return s;
}
const char* typeName(uint8_t type) {
    switch(type){case 0:return "d";case 1:return "f";case 2:return "i";case 3:return "l";case 4:return "b";case 5:return "v";case 6:return "s";case 15:return "e";default:return "?";}
}
std::string quoted(const std::string& s) {
    std::string r="\"";size_t n=std::min<size_t>(s.size(),240);
    for(size_t i=0;i<n;++i){const unsigned char c=s[i];if(c=='\n')r+="\\n";else if(c=='\r')r+="\\r";else if(c=='\t')r+="\\t";else if(c=='\\')r+="\\\\";else if(c=='\"')r+="\\\"";else if(c<32)r+='?';else r+=s[i];}
    if(n<s.size())r+="...";r+='\"';return r;
}
void immediate(Instruction& out,uint64_t value,uint16_t width=32,bool signedValue=false) {
    TypedOperand op;op.kind=OperandKind::Immediate;op.access=OperandAccess::Read;op.immediate=value;op.widthBits=width;op.immediateSigned=signedValue;out.typedOperands.push_back(std::move(op));
}
void target(Instruction& out,uint64_t address) {out.flow.directTargetValid=out.branchTargetValid=true;out.flow.directTarget=out.branchTarget=address;}
bool addSigned(uint64_t base,int64_t offset,uint64_t& value) {
    if(offset<0){if(base<uint64_t(-offset))return false;value=base-uint64_t(-offset);}
    else {if(uint64_t(offset)>(std::numeric_limits<uint64_t>::max)()-base)return false;value=base+uint64_t(offset);}return true;
}
}

GmlDisassembler::GmlDisassembler(const DecoderConfig& config) {
    if(config.byteOrder!=ByteOrder::Little)error_="GameMaker bytecode supports little-endian words only";
    else if(config.features!=DecoderFeatures{})error_="Native ISA features do not apply to GameMaker bytecode";
}
void GmlDisassembler::attachArchive(std::shared_ptr<const GameMakerArchive> archive) {archive_=std::move(archive);}
bool GmlDisassembler::ready() const {return error_.empty() && (!archive_ || (archive_->ok && archive_->bytecodeSupported));}
std::string_view GmlDisassembler::errorMessage() const {
    if(!error_.empty())return error_;
    if(archive_ && !archive_->ok)return archive_->error;
    if(archive_ && !archive_->bytecodeSupported)return "Unsupported GameMaker bytecode version; native decoding is disabled";
    return {};
}
bool GmlDisassembler::decodeOne(const uint8_t* data,size_t size,uint64_t va,Instruction& out) {
    out={};if(!ready() || !data || size<4 || (va&3))return false;
    uint32_t w=word(data),len=GmlEncodedInstructionLength(w,archive_?archive_->bytecodeVersion:17);
    if(!len || len>size || len-1>(std::numeric_limits<uint64_t>::max)()-va)return false;
    const GameMakerCode* body=archive_?archive_->codeAtOffset(va):nullptr;
    if(archive_ && (!body || !archive_->isInstructionOffset(va) || len>body->bytecodeOffset+body->bytecodeLength-va))return false;
    uint8_t op=uint8_t(w>>24),t1=uint8_t(w>>16)&15,t2=uint8_t(w>>20)&15;
    out.address=va;out.length=len;out.bytes=bytes(data,len);
    const char* name=nullptr;
    switch(op) {
        case 7:name="conv";break;case 8:name="mul";break;case 9:name="div";break;case 10:name="rem";break;case 11:name="mod";break;
        case 12:name="add";break;case 13:name="sub";break;case 14:name="and";break;case 15:name="or";break;case 16:name="xor";break;
        case 17:name="neg";break;case 18:name="not";break;case 19:name="shl";break;case 20:name="shr";break;case 21:name="cmp";break;
        case 0x45:name=t1==15?"pop.swap":"pop";break;case 0x84:name="pushi";break;case 0x86:name="dup";break;
        case 0x99:name="callv";break;case 0x9c:name="ret";break;case 0x9d:name="exit";break;case 0x9e:name="popz";break;
        case 0xb6:name="b";break;case 0xb7:name="bt";break;case 0xb8:name="bf";break;case 0xba:name="pushenv";break;case 0xbb:name="popenv";break;
        case 0xc0:name="push";break;case 0xc1:name="pushloc";break;case 0xc2:name="pushglb";break;case 0xc3:name="pushbltn";break;case 0xd9:name="call";break;
        case 0xff: {
            static const char* extended[]={"chkindex","pushaf","popaf","pushac","setowner","isstaticok","setstatic","savearef","restorearef","chknullish","pushref"};
            int16_t sub=static_cast<int16_t>(w);if(sub>=-11 && sub<=-1)name=extended[-sub-1];
            else {name="break.unsupported";out.comment="Unrecognized GML extended opcode; semantics unavailable";out.operands=std::to_string(sub);}
            if(len==8){if(!out.operands.empty())out.operands+=", ";out.operands+=hex(word(data+4));immediate(out,word(data+4));}
            break;
        }
        default:return false;
    }
    out.mnemonic=name;
    const bool branch=(op>=0xb6 && op<=0xb8) || op==0xba || op==0xbb;
    if(branch) {
        if(op==0xbb && (w&0xffffff)==0xf00000) {out.operands="exit";out.comment="Leaves the current with-environment; execution falls through";return true;}
        int32_t disp=static_cast<int32_t>(w&0x7fffff);if(disp&0x400000)disp|=static_cast<int32_t>(0xff800000u);
        int64_t delta=int64_t(disp)*4;uint64_t to=0;
        out.isBranch=true;out.flow.kind=op==0xb6?FlowKind::UnconditionalBranch:FlowKind::ConditionalBranch;
        bool valid=addSigned(va,delta,to);
        if(valid && body)valid=to>=body->bytecodeOffset && to<=body->bytecodeOffset+body->bytecodeLength && (to==body->bytecodeOffset+body->bytecodeLength || archive_->isInstructionOffset(to));
        if(valid){target(out,to);out.operands=hex(to);}else{out.operands="invalid target ("+std::to_string(delta)+")";out.comment="GML branch target is outside its body or inside an operand";}
        immediate(out,uint64_t(delta),32,true);out.typedOperands.back().pcRelative=true;
        if(op==0xba || op==0xbb)out.comment+=(out.comment.empty()?"":"; ")+std::string("with-environment iteration control");
        return true;
    }
    if(op==0x9c || op==0x9d){out.isBranch=out.isRet=true;out.flow.kind=FlowKind::Return;}
    if(op==0x99 || op==0xd9){out.isBranch=out.isCall=true;out.flow.kind=FlowKind::IndirectCall;}
    if(op!=0xff) {
        out.mnemonic+='.';out.mnemonic+=typeName(t1);
        if((op>=7 && op<=0x15 && op!=17 && op!=18) || (op==0x45 && t1!=15)) {out.mnemonic+='.';out.mnemonic+=typeName(t2);}
    }
    if(op==0x15) {
        static const char* comparisons[]={"?","lt","lte","eq","neq","gte","gt"};uint32_t cmp=(w>>8)&255;
        out.operands=cmp<7?comparisons[cmp]:"unsupported comparison";immediate(out,cmp,8);
    }
    if(op==0x86){out.operands=std::to_string(w&255);if(w&0xff00)out.operands+=", move="+std::to_string((w>>8)&255);immediate(out,w&0xffff,16);}
    if(op==0x99){out.operands="argc="+std::to_string(w&255);immediate(out,w&255,8);}
    if(op==0x45 && t1==15){out.operands=std::to_string(w&0xffff);immediate(out,w&0xffff,16);}
    const bool push=op==0x84 || (op>=0xc0 && op<=0xc3);
    const auto* ref=archive_?archive_->referenceAtOffset(va):nullptr;
    if(ref && ref->kind==GmlReferenceKind::Variable && ref->symbolIndex<archive_->variables.size()) {
        const auto& v=archive_->variables[ref->symbolIndex];
        const int16_t scope=static_cast<int16_t>(w);
        out.operands=std::string(GmlScopeName(scope))+"."+v.name;
        if(scope>=0)out.operands="instance["+std::to_string(scope)+"]."+v.name;
        if(ref->referenceType!=0xa0)out.operands+=" [mode="+hex(ref->referenceType)+"]";
        out.comment="VARI #"+std::to_string(v.index)+", id="+std::to_string(v.variableId);
        TypedOperand operand;operand.kind=OperandKind::Memory;operand.access=op==0x45?OperandAccess::Write:OperandAccess::Read;
        operand.displacement=static_cast<int64_t>(v.recordOffset);operand.displacementValid=true;out.typedOperands.push_back(std::move(operand));
    } else if(ref && ref->kind==GmlReferenceKind::Function && ref->symbolIndex<archive_->functions.size()) {
        out.typedOperands.clear(); // A chain-link word is not the pushed function's numeric value.
        const auto& f=archive_->functions[ref->symbolIndex];out.operands=f.name;
        if(op==0xd9)out.operands+=" (argc="+std::to_string(w&0xffff)+")";
        out.comment="FUNC #"+std::to_string(f.index);
        if(f.codeIndex<archive_->code.size() && archive_->isInstructionOffset(archive_->code[f.codeIndex].entryFileOffset())) {
            uint64_t to=archive_->code[f.codeIndex].entryFileOffset();
            if(op==0xd9){out.flow.kind=FlowKind::DirectCall;target(out,to);}
            TypedOperand operand;operand.kind=OperandKind::Pointer;operand.access=OperandAccess::Read;operand.immediate=to;out.typedOperands.push_back(std::move(operand));
        }
    } else if(push) {
        if(t1==15){int16_t n=static_cast<int16_t>(w);out.operands=std::to_string(n);immediate(out,uint64_t(int64_t(n)),16,true);}
        else if(t1==0){uint64_t raw=qword(data+4);double d;std::memcpy(&d,&raw,8);char b[64];std::snprintf(b,sizeof(b),"%.17g",d);out.operands=b;immediate(out,raw,64);}
        else if(t1==3){out.operands=std::to_string(static_cast<int64_t>(qword(data+4)));immediate(out,qword(data+4),64,true);}
        else if(t1==2){int32_t n=static_cast<int32_t>(word(data+4));out.operands=std::to_string(n);immediate(out,uint64_t(int64_t(n)),32,true);}
        else if(t1==6){uint32_t index=word(data+4);out.operands="STRG #"+std::to_string(index);immediate(out,index);
            if(archive_ && index<archive_->strings.size()){out.comment=quoted(archive_->strings[index].text);out.typedOperands.back().kind=OperandKind::Pointer;out.typedOperands.back().immediate=archive_->strings[index].fileOffset;}}
        else {out.operands="unresolved variable reference "+hex(word(data+4));out.comment="No validated VARI chain for this instruction";}
    } else if(op==0xd9){out.operands="unresolved function (argc="+std::to_string(w&0xffff)+")";out.comment="No validated FUNC chain for this instruction";}
    else if(op==0x45 && t1!=15){out.operands="unresolved variable reference "+hex(word(data+4));out.comment="No validated VARI chain for this instruction";}
    return true;
}
std::vector<Instruction> GmlDisassembler::disassemble(const uint8_t* data,size_t size,uint64_t va,size_t max) {
    std::vector<Instruction> result;if(!ready() || !data)return result;size_t p=0;
    while(p<size && (!max || result.size()<max)) {
        if(p>(std::numeric_limits<uint64_t>::max)()-va)break;
        Instruction in;
        if(!decodeOne(data+p,size-p,va+p,in)) {
            in.address=va+p;in.length=static_cast<uint32_t>(std::min<size_t>(4,size-p));in.bytes=bytes(data+p,in.length);
            in.mnemonic="gml.unsupported";in.operands=in.bytes;in.comment="Unsupported, unaligned, or truncated GML instruction; no native fallback";
        }
        p+=in.length;result.push_back(std::move(in));
    }
    return result;
}
void AttachGameMakerArchive(IDisassembler& dis,std::shared_ptr<const GameMakerArchive> archive) {if(auto* gml=dynamic_cast<GmlDisassembler*>(&dis))gml->attachArchive(std::move(archive));}
} // namespace ds
