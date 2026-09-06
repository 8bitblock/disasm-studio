#include "Core/GameMakerHelperImage.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#endif

static int failures=0;
#define CHECK(x) do{if(!(x)){std::printf("FAIL %d: %s\n",__LINE__,#x);++failures;}}while(0)
static void set16(std::vector<uint8_t>& b,size_t p,uint16_t n){b[p]=uint8_t(n);b[p+1]=uint8_t(n>>8);}
static void set32(std::vector<uint8_t>& b,size_t p,uint32_t n){for(unsigned i=0;i<4;++i)b[p+i]=uint8_t(n>>(8*i));}
static std::vector<uint8_t> fixture(){
    std::vector<uint8_t> b(1024);b[0]='M';b[1]='Z';set32(b,0x3c,128);b[128]='P';b[129]='E';
    set16(b,132,0x8664);set16(b,134,1);set16(b,148,240);set16(b,150,0x2022);
    set16(b,152,0x20b);set32(b,168,4096);set32(b,184,4096);set32(b,188,512);set32(b,208,8192);set32(b,212,512);
    b[392]='.';b[393]='t';b[394]='e';b[395]='x';b[396]='t';set32(b,400,1);set32(b,404,4096);set32(b,408,512);set32(b,412,512);set32(b,428,0x60000020);b[512]=0xc3;return b;
}
static std::span<const uint8_t> bytes(const std::string& text){return {reinterpret_cast<const uint8_t*>(text.data()),text.size()};}
int main(int argc,char** argv){
    CHECK(ds::GameMakerHelperSha256({})=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(ds::GameMakerHelperSha256(bytes("abc"))=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(ds::GameMakerHelperSha256(bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))=="248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(ds::GameMakerHelperSha256(bytes(std::string(1'000'000,'a')))=="cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    auto b=fixture();std::string error;CHECK(ds::ValidateGameMakerHelperImage(b,error));CHECK(error.empty());
    auto malformed=b;set16(malformed,132,0x14c);CHECK(!ds::ValidateGameMakerHelperImage(malformed,error));
    malformed=b;set16(malformed,150,2);CHECK(!ds::ValidateGameMakerHelperImage(malformed,error));
    malformed=b;set32(malformed,0x3c,UINT32_MAX);CHECK(!ds::ValidateGameMakerHelperImage(malformed,error));
    malformed=b;set32(malformed,408,0xfffffe00);CHECK(!ds::ValidateGameMakerHelperImage(malformed,error));
    malformed=b;set32(malformed,428,0x40000020);CHECK(!ds::ValidateGameMakerHelperImage(malformed,error));
    malformed=b;set16(malformed,134,97);CHECK(!ds::ValidateGameMakerHelperImage(malformed,error));
    malformed=b;set32(malformed,184,0x3000);CHECK(!ds::ValidateGameMakerHelperImage(malformed,error));
    for(size_t n=0;n<1024;++n)CHECK(!ds::ValidateGameMakerHelperImage({b.data(),n},error));
#ifdef _WIN32
    namespace fs=std::filesystem;
    auto pathString=[](const fs::path& p){auto u=p.u8string();return std::string(reinterpret_cast<const char*>(u.data()),u.size());};
    auto fromUtf8=[](const std::string& p){return fs::path(std::u8string(reinterpret_cast<const char8_t*>(p.data()),p.size()));};
    fs::path testRoot=fs::temp_directory_path()/("disasm-gml-helper-test-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(GetTickCount64()));
    std::error_code ec;fs::create_directory(testRoot,ec);CHECK(!ec);
    fs::path cache=testRoot/"private-cache";std::string path;
    CHECK(ds::ExtractGameMakerHelperBytes(b,pathString(cache),path,error));
    if(!error.empty())std::printf("extract error: %s\n",error.c_str());
    CHECK(!path.empty());std::string first=path;CHECK(fs::exists(fromUtf8(path)));
    CHECK(fromUtf8(path).parent_path()==cache);CHECK(path.find(ds::GameMakerHelperSha256(b))!=std::string::npos);
    CHECK(ds::ExtractGameMakerHelperBytes(b,pathString(cache),path,error));CHECK(path==first);
    {std::ofstream corrupt(fromUtf8(path),std::ios::binary|std::ios::trunc);corrupt<<"corrupt cache";}
    CHECK(ds::ExtractGameMakerHelperBytes(b,pathString(cache),path,error));CHECK(path==first);
    {std::ifstream read(fromUtf8(path),std::ios::binary);std::vector<uint8_t> content((std::istreambuf_iterator<char>(read)),{});CHECK(content==b);}
    // A hardlink is rejected even if its contents happen to match the resource.
    fs::path alias=testRoot/"alias.dll";CHECK(CreateHardLinkW(alias.c_str(),fromUtf8(path).c_str(),nullptr)!=FALSE);
    CHECK(!ds::ExtractGameMakerHelperBytes(b,pathString(cache),path,error));CHECK(path.empty());CHECK(error.find("single link")!=std::string::npos);fs::remove(alias,ec);
    std::string relative="private-cache";CHECK(!ds::ExtractGameMakerHelperBytes(b,relative,path,error));CHECK(path.empty());
    CHECK(!ds::ExtractGameMakerHelperBytes(b,pathString(testRoot/".."/"escape"),path,error));CHECK(path.empty());
    CHECK(!ds::ExtractGameMakerHelperBytes(b,"\\\\localhost\\C$\\test",path,error));
    CHECK(!ds::ExtractGameMakerHelperBytes(b,"C:\\",path,error));
    CHECK(!ds::ExtractGameMakerHelperBytes(malformed,pathString(cache),path,error));
    // A directory cannot masquerade as the final digest-named DLL.
    fs::remove(fromUtf8(first),ec);CHECK(!ec);fs::create_directory(fromUtf8(first),ec);CHECK(!ec);
    CHECK(!ds::ExtractGameMakerHelperBytes(b,pathString(cache),path,error));CHECK(path.empty());fs::remove(fromUtf8(first),ec);
    CHECK(ds::ExtractGameMakerHelperBytes(b,pathString(cache),path,error));
    // The cache DACL is protected and grants access only to user and SYSTEM.
    PSECURITY_DESCRIPTOR descriptor=nullptr;PACL acl=nullptr;CHECK(GetNamedSecurityInfoW(const_cast<wchar_t*>(cache.c_str()),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&acl,nullptr,&descriptor)==ERROR_SUCCESS);
    if(descriptor){SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;CHECK(GetSecurityDescriptorControl(descriptor,&control,&revision));CHECK((control&SE_DACL_PROTECTED)!=0);CHECK(acl && acl->AceCount==2);LocalFree(descriptor);}
    // Developer Mode or an elevated test account permits symlink creation; when
    // unavailable, all other extraction and ownership checks still execute.
    fs::path linked=testRoot/"redirect";
    if(CreateSymbolicLinkW(linked.c_str(),cache.c_str(),SYMBOLIC_LINK_FLAG_DIRECTORY|SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)){
        CHECK(!ds::ExtractGameMakerHelperBytes(b,pathString(linked),path,error));CHECK(path.empty());fs::remove(linked,ec);
    }
    if(argc>1){std::ifstream stream(argv[1],std::ios::binary);std::vector<uint8_t> real((std::istreambuf_iterator<char>(stream)),{});CHECK(ds::ValidateGameMakerHelperImage(real,error));if(!error.empty())std::printf("actual validation: %s\n",error.c_str());CHECK(ds::ExtractGameMakerHelperBytes(real,pathString(cache),path,error));std::printf("actual helper: size=%zu sha256=%s extracted=%s\n",real.size(),ds::GameMakerHelperSha256(real).c_str(),path.c_str());}
    // The unique test directory was constructed under the resolved temp root.
    fs::path resolved=fs::weakly_canonical(testRoot,ec),parent=fs::weakly_canonical(fs::temp_directory_path(),ec);
    CHECK(!ec && resolved.parent_path()==parent);
    if(!ec && resolved.parent_path()==parent)fs::remove_all(resolved,ec);CHECK(!ec);
#else
    (void)argc;(void)argv;
#endif
    std::printf("gamemaker_helper_image_test: %d failure(s)\n",failures);return failures?1:0;
}
