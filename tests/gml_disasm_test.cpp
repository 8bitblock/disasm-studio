#include "Disasm/GmlDisassembler.h"
#include "Core/CFG.h"
#include "Core/GmlInstructionText.h"
#include "Tabs/DataRef.h"
#include "gamemaker_fixture.h"
#include <cstdio>
#include <fstream>
#include <iterator>
#include <limits>
static int failures=0;
#define CHECK(x) do{if(!(x)){std::printf("FAIL %d: %s\n",__LINE__,#x);++failures;}}while(0)

static void CheckReadableInstructions(const std::vector<ds::Instruction>& fixture) {
    if (fixture.size() != 8) return;
    const auto variable = ds::DescribeGmlInstruction(fixture[5]);
    CHECK(variable.operation == "Read variable");
    CHECK(variable.operands == "self.money");
    CHECK(variable.explanation.find(".v = dynamic GameMaker value") != std::string::npos);
    CHECK(fixture[5].mnemonic == "push.v" && fixture[5].operands == "self.money");
    const auto string = ds::DescribeGmlInstruction(fixture[3]);
    CHECK(string.operation == "Load constant" && string.operands == "\"hello GML\"");
    CHECK(fixture[3].operands == "STRG #4");
    CHECK(ds::DescribeGmlInstruction(fixture[1]).operands == "7");
    const auto call = ds::DescribeGmlInstruction(fixture[6]);
    CHECK(call.operation == "Call function" && call.operands == "scr_GiveMoney (0 arguments)");
    CHECK(fixture[6].flow.kind == ds::FlowKind::DirectCall && fixture[6].branchTargetValid);

    // Reference-bearing pushes are not all constant values or variable reads.
    auto reference = fixture[5]; reference.mnemonic = "push.i";
    CHECK(ds::DescribeGmlInstruction(reference).operation == "Load variable identifier");
    reference = fixture[6]; reference.mnemonic = "push.i"; reference.operands = "scr_GiveMoney";
    CHECK(ds::DescribeGmlInstruction(reference).operation == "Load function reference");
    reference = fixture[6]; reference.operands = "argc=9 (argc=1)";
    CHECK(ds::DescribeGmlInstruction(reference).operands == "argc=9 (1 argument)");
    reference = fixture[5]; reference.mnemonic = "pop.v.v";
    reference.operands += " [mode=0x0]";
    auto write = ds::DescribeGmlInstruction(reference);
    CHECK(write.operation == "Write variable" && write.operands == reference.operands);
    CHECK(write.explanation.find("not known here") != std::string::npos);
    reference = fixture[3]; reference.comment.clear();
    const auto missingString = ds::DescribeGmlInstruction(reference);
    CHECK(missingString.operands == "STRG #4");
    CHECK(missingString.explanation.find("unresolved") != std::string::npos);

    ds::GmlDisassembler decoder;
    std::vector<uint8_t> bytes(12, 0);
    auto decode = [&](uint32_t word, uint64_t address = 0) {
        gmltest::Set32(bytes, 0, word);
        ds::Instruction in;
        CHECK(decoder.decodeOne(bytes.data(), bytes.size(), address, in));
        return in;
    };
    auto unresolved = ds::DescribeGmlInstruction(decode(0xc005ffff));
    CHECK(unresolved.operation == "Read variable");
    CHECK(unresolved.operands.starts_with("unresolved variable reference"));
    CHECK(unresolved.explanation.find("not resolved") != std::string::npos);
    auto conditional = decode(0xb87fffff, 4);
    auto branch = ds::DescribeGmlInstruction(conditional);
    CHECK(branch.operation == "Jump if false" && branch.operands == "0x0");
    CHECK(branch.explanation.find("could not validate") == std::string::npos);
    CHECK(conditional.flow.directTargetValid && conditional.flow.directTarget == 0);
    branch = ds::DescribeGmlInstruction(decode(0xb87fffff));
    CHECK(branch.operands.starts_with("invalid target"));
    CHECK(branch.explanation.find("could not validate") != std::string::npos);
    CHECK(ds::DescribeGmlInstruction(decode(0xbbf00000)).operation == "Leave with loop");
    CHECK(ds::DescribeGmlInstruction(decode(0xba000002)).operation == "Begin with loop");
    CHECK(ds::DescribeGmlInstruction(decode(0xbb000002)).operation == "Next with instance");
    CHECK(ds::DescribeGmlInstruction(decode(0x99050001)).operands == "1 argument");

    // Preserve GML's quotient/remainder distinction and comparison operand order.
    CHECK(ds::DescribeGmlInstruction(decode(0x0a220000)).operation == "Integer divide");
    CHECK(ds::DescribeGmlInstruction(decode(0x0b220000)).operation == "Find remainder");
    auto convert = ds::DescribeGmlInstruction(decode(0x07520000));
    CHECK(convert.operands.starts_with("32-bit signed integer -> dynamic GameMaker value"));
    const char* comparisons[] = {"<", "<=", "==", "!=", ">=", ">"};
    for (unsigned i = 1; i <= 6; ++i) {
        const auto compare = ds::DescribeGmlInstruction(decode(0x15550000 | (i << 8)));
        CHECK(compare.operation == "Compare values");
        CHECK(compare.operands == std::string("left ") + comparisons[i - 1] + " right");
    }
    CHECK(ds::DescribeGmlInstruction(decode(0x15550700)).operation == "Unknown comparison");
    const char* types[] = {"64-bit floating-point", "32-bit floating-point", "32-bit signed", "64-bit signed", "boolean", "dynamic GameMaker", "string"};
    for (unsigned i = 0; i != 7; ++i)
        CHECK(ds::DescribeGmlInstruction(decode(0x9e000000 | (i << 16))).explanation.find(types[i]) != std::string::npos);
    CHECK(ds::DescribeGmlInstruction(decode(0x840fffff)).explanation.find("signed 16-bit immediate") != std::string::npos);

    // Swaps do not write variables; .e has a special meaning for stack operations.
    auto swap = ds::DescribeGmlInstruction(decode(0x450f0005));
    CHECK(swap.operation == "Reorder temporary values");
    CHECK(swap.explanation.find("signed 16-bit") == std::string::npos);
    CHECK(ds::DescribeGmlInstruction(decode(0x86050000)).operation == "Copy temporary values");
    CHECK(ds::DescribeGmlInstruction(decode(0x86058000)).operation == "Copy temporary values");
    CHECK(ds::DescribeGmlInstruction(decode(0x86058801)).operation == "Reorder temporary values");
    swap = ds::DescribeGmlInstruction(decode(0x860f0801));
    CHECK(swap.operation == "Reorder temporary values");
    CHECK(swap.explanation.find("special encoding for dynamic") != std::string::npos);

    // Extended array operations describe their role without inventing index/owner identities.
    const char* extended[] = {"Check array index", "Read array element", "Write array element", "Read nested array",
        "Set array owner", "Check static initialization", "Mark static initialization", "Save array reference",
        "Restore array reference", "Check for missing value", "Load reference"};
    for (int16_t sub = -1; sub >= -11; --sub) {
        const auto text = ds::DescribeGmlInstruction(decode(0xff0f0000 | uint16_t(sub)));
        CHECK(text.operation == extended[-sub - 1] && !text.explanation.empty());
    }
    CHECK(ds::DescribeGmlInstruction(decode(0xff0f002a)).operation == "Unsupported instruction");
    ds::Instruction unknown; unknown.mnemonic = "future.opcode"; unknown.operands = "raw operand";
    CHECK(ds::DescribeGmlInstruction(unknown).operation == "Unknown instruction");
    CHECK(ds::DescribeGmlInstruction(unknown).operands == "raw operand");
}

int main(int argc,char** argv){
    auto f=gmltest::BuildArchive();auto a=std::make_shared<ds::GameMakerArchive>(ds::ParseGameMakerArchive(f.bytes.data(),f.bytes.size()));ds::GmlDisassembler dis;dis.attachArchive(a);
    auto ins=dis.disassemble(f.bytes.data()+f.rootOffset,f.rootLength,f.rootOffset);CHECK(ins.size()==8);
    CheckReadableInstructions(ins);
    if(ins.size()==8){CHECK(ins[0].flow.kind==ds::FlowKind::UnconditionalBranch);CHECK(ins[0].branchTarget==f.rootOffset+12);CHECK(ins[1].mnemonic=="pushi.e");CHECK(ins[2].isRet);CHECK(ins[3].comment.find("hello GML")!=std::string::npos);CHECK(ins[5].operands=="self.money");CHECK(ins[6].flow.kind==ds::FlowKind::DirectCall);CHECK(ins[6].branchTarget==f.childOffset);}
    auto graph=ds::BuildCFG(f.bytes.data()+f.rootOffset,f.rootLength,f.rootOffset,dis);
    if(ins.size()==8){uint64_t target=0;CHECK(ds::TryGetInstrImmRef(ins[3],target));CHECK(target==a->strings[4].fileOffset);CHECK(ds::instrRefsAddr(ins[3],target));CHECK(ds::TryGetInstrDataRef(ins[5],target) && target==a->variables[0].recordOffset);}
    CHECK(graph.complete);CHECK(graph.blocks.size()==3);
    if(graph.blocks.size()==3){CHECK(graph.blocks[0].succ.size()==1);CHECK(graph.blocks[0].succ[0]==2);CHECK(graph.blocks[1].isReturn);CHECK(graph.blocks[2].isReturn);CHECK(graph.blocks[1].succ.empty());}
    ds::Instruction out;CHECK(!dis.decodeOne(f.bytes.data()+f.callInstruction,4,f.callInstruction,out));CHECK(!dis.decodeOne(f.bytes.data()+f.rootOffset,4,f.rootOffset+1,out));
    ds::GmlDisassembler raw;std::vector<uint8_t> b;gmltest::Append32(b,0xb67fffff);CHECK(raw.decodeOne(b.data(),4,4,out));CHECK(out.branchTargetValid && out.branchTarget==0);CHECK(raw.decodeOne(b.data(),4,0,out));CHECK(!out.branchTargetValid);
    b.clear();gmltest::Append32(b,0xc0030000);gmltest::Append32(b,0xffffffff);gmltest::Append32(b,0xffffffff);CHECK(raw.decodeOne(b.data(),b.size(),0,out));CHECK(out.length==12 && out.operands=="-1");CHECK(!raw.decodeOne(b.data(),11,0,out));
    b.clear();gmltest::Append32(b,0xff02fff5);gmltest::Append32(b,0x123);CHECK(raw.decodeOne(b.data(),8,0,out));CHECK(out.mnemonic=="pushref");
    b.clear();gmltest::Append32(b,0xbbb00000);CHECK(raw.decodeOne(b.data(),4,0,out));
    gmltest::Set32(b,0,0xbbf00000);CHECK(raw.decodeOne(b.data(),4,0,out));CHECK(out.flow.kind==ds::FlowKind::None);
    gmltest::Set32(b,0,0x01000000);auto bad=raw.disassemble(b.data(),4,0);CHECK(bad.size()==1 && bad[0].mnemonic=="gml.unsupported");
    gmltest::Set32(b,0,0xc0040000);CHECK(!raw.decodeOne(b.data(),4,0,out));
    // Every supported modern opcode, including its true immediate width.
    const uint8_t simple[]={7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,0x86,0x99,0x9c,0x9d,0x9e};
    for(uint8_t op:simple){b.assign(4,0);gmltest::Set32(b,0,(uint32_t(op)<<24)|0x00050300);CHECK(raw.decodeOne(b.data(),4,0,out));CHECK(out.length==4);}
    for(unsigned op:{0xc0,0xc1,0xc2,0xc3,0x84})for(unsigned type:{0,2,3,5,6,15}){
        uint32_t size=type==0 || type==3?12:type==15?4:8;b.assign(size,0);gmltest::Set32(b,0,(uint32_t(op)<<24)|(uint32_t(type)<<16));CHECK(raw.decodeOne(b.data(),size,0,out));CHECK(out.length==size);CHECK(!raw.decodeOne(b.data(),size-1,0,out));
    }
    b.assign(8,0);gmltest::Set32(b,0,0x450f0002);CHECK(raw.decodeOne(b.data(),8,0,out));CHECK(out.length==4);CHECK(out.operands=="2");
    gmltest::Set32(b,0,0x4555ffff);CHECK(raw.decodeOne(b.data(),8,0,out));CHECK(out.length==8);
    gmltest::Set32(b,0,0x9c0e0000);CHECK(!raw.decodeOne(b.data(),8,0,out));
    // Conditional environment loops have both a target and a fallthrough; special cleanup does not jump.
    for(unsigned op:{0xb7,0xb8,0xba,0xbb}){gmltest::Set32(b,0,(uint32_t(op)<<24)|2);CHECK(raw.decodeOne(b.data(),4,0,out));CHECK(out.flow.kind==ds::FlowKind::ConditionalBranch && out.branchTarget==8);}
    for(int16_t sub=-1;sub>=-11;--sub){gmltest::Set32(b,0,0xff0f0000|uint16_t(sub));CHECK(raw.decodeOne(b.data(),4,0,out));CHECK(out.mnemonic.find("unsupported")==std::string::npos);}
    gmltest::Set32(b,0,0xff0f002a);CHECK(raw.decodeOne(b.data(),4,0,out));CHECK(out.mnemonic=="break.unsupported");
    CHECK(!raw.decodeOne(b.data(),4,(std::numeric_limits<uint64_t>::max)()-2,out));
    auto invalidBranch=f.bytes;gmltest::Set32(invalidBranch,f.rootOffset,0xb6000004);ds::GmlDisassembler invalidDis;invalidDis.attachArchive(std::make_shared<ds::GameMakerArchive>(ds::ParseGameMakerArchive(invalidBranch.data(),invalidBranch.size())));CHECK(invalidDis.decodeOne(invalidBranch.data()+f.rootOffset,4,f.rootOffset,out));CHECK(!out.branchTargetValid);CHECK(out.comment.find("operand")!=std::string::npos);
    ds::DecoderConfig config;config.arch=ds::Arch::GML;config.byteOrder=ds::ByteOrder::Big;ds::GmlDisassembler big(config);CHECK(!big.ready());CHECK(!big.errorMessage().empty());
    a->bytecodeSupported=false;CHECK(!dis.ready());CHECK(dis.disassemble(f.bytes.data(),f.bytes.size(),0).empty());
    if(argc>1){std::ifstream stream(argv[1],std::ios::binary);std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(stream)),{});auto actual=std::make_shared<ds::GameMakerArchive>(ds::ParseGameMakerArchive(bytes.data(),bytes.size()));CHECK(actual->ok);dis.attachArchive(actual);uint64_t count=0,calls=0;for(uint32_t id:actual->rootCodeIndices){const auto& code=actual->code[id];for(uint64_t pos=code.bytecodeOffset;pos<code.bytecodeOffset+code.bytecodeLength;){if(!dis.decodeOne(bytes.data()+pos,code.bytecodeOffset+code.bytecodeLength-pos,pos,out)){CHECK(false);break;}if(out.flow.kind==ds::FlowKind::DirectCall)++calls;++count;pos+=out.length;}}std::printf("actual decoded=%llu resolved calls=%llu\n",static_cast<unsigned long long>(count),static_cast<unsigned long long>(calls));CHECK(count==actual->instructionOffsets.size());}
    std::printf("gml_disasm_test: %d failure(s)\n",failures);return failures?1:0;
}
