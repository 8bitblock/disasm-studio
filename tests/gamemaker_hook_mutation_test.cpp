#include "Core/GameMakerHookMutation.h"
#include <cstdio>
using namespace ds;
static int failures=0;
#define CHECK(x) do{if(!(x)){std::printf("FAIL %d: %s\n",__LINE__,#x);++failures;}}while(0)
static constexpr std::array<uint8_t,6> original{0x89,0x8b,0x9c,0,0,0},patch{0xe9,1,2,3,4,0x90};
struct Fake {
    std::array<uint8_t,6> bytes=original;
    uint32_t protection=0x20;
    int reads=0,writes=0,protects=0,flushes=0;
    int failedRead=0,failedWrite=0,failedProtect=0,failedFlush=0;
    size_t failedWriteBytes=0;
    bool failRollback=false;
    static bool read(void* p,uint64_t,void* out,size_t n){auto& f=*(Fake*)p;if(++f.reads==f.failedRead)return false;std::memcpy(out,f.bytes.data(),n);return true;}
    static bool write(void* p,uint64_t,const void* in,size_t n){auto& f=*(Fake*)p;++f.writes;
        if(f.writes==f.failedWrite){std::memcpy(f.bytes.data(),in,f.failedWriteBytes);return false;}
        if(f.failRollback && f.writes==2)return false;
        std::memcpy(f.bytes.data(),in,n);return true;}
    static bool protect(void* p,uint64_t,size_t,uint32_t next,uint32_t* old){auto& f=*(Fake*)p;
        if(++f.protects==f.failedProtect)return false;*old=f.protection;f.protection=next;return true;}
    static bool flush(void* p,uint64_t,size_t){auto& f=*(Fake*)p;return ++f.flushes!=f.failedFlush;}
    GmlHookMutationResult install(){return MutateGmlHookBytes({this,read,write,protect,flush},0x1000,original,patch,0x40);}
};
int main(){
    Fake f;auto r=f.install();CHECK(r.success && r.mutationAttempted && r.originalProtectionKnown && r.originalProtection==0x20);
    CHECK(f.bytes==patch && f.protection==0x20 && f.flushes==1);
    f={};f.failedRead=1;r=f.install();CHECK(!r.success && !r.mutationAttempted && !r.originalProtectionKnown && !f.writes && !f.protects);
    f={};f.bytes[0]=0xcc;r=f.install();CHECK(!r.success && !f.writes && !f.protects && f.bytes[0]==0xcc);
    f={};f.failedProtect=1;r=f.install();CHECK(!r.success && !r.mutationAttempted && !f.writes);
    for(size_t written=0;written<=patch.size();++written){
        f={};f.failedWrite=1;f.failedWriteBytes=written;r=f.install();
        CHECK(!r.success && r.mutationAttempted && r.originalProtectionKnown && f.writes==2 && f.bytes==original && f.protection==0x20);
        f={};f.failedWrite=1;f.failedWriteBytes=written;f.failRollback=true;r=f.install();
        CHECK(!r.success && r.mutationAttempted && f.writes==2 && f.protection==0x20);
        for(size_t i=0;i<f.bytes.size();++i)CHECK(f.bytes[i]==(i<written?patch[i]:original[i]));
    }
    f={};f.failedProtect=2;r=f.install();CHECK(!r.success && r.mutationAttempted && f.bytes==patch && f.protection==0x40 && f.flushes==1);
    f={};f.failedFlush=1;r=f.install();CHECK(!r.success && r.mutationAttempted && f.bytes==patch && f.protection==0x20);
    f={};f.failedWrite=1;f.failedWriteBytes=3;f.failedProtect=2;f.failedFlush=1;r=f.install();
    CHECK(!r.success && r.mutationAttempted && f.bytes==original && f.protection==0x40);
    // A later exact-owned restore uses the same transaction and original bytes.
    f={};CHECK(f.install().success);
    r=MutateGmlHookBytes({&f,Fake::read,Fake::write,Fake::protect,Fake::flush},0x1000,patch,original,0x40);
    CHECK(r.success && f.bytes==original && f.protection==0x20);
    f.bytes[2]=0xcc;const auto before=f.bytes;
    r=MutateGmlHookBytes({&f,Fake::read,Fake::write,Fake::protect,Fake::flush},0x1000,patch,original,0x40);
    CHECK(!r.success && !r.mutationAttempted && f.bytes==before);
    std::printf("gamemaker_hook_mutation_test: %s\n",failures?"FAILED":"all checks passed");return failures?1:0;
}
