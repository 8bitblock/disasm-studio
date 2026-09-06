#include "GameMakerHelperImage.h"
#include "../resource.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#endif

namespace ds {
static_assert(GameMakerHelperResourceId==IDR_GML_HELPER);
namespace {
constexpr std::array<uint32_t,64> RoundConstants={
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
uint32_t rotate(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
void compress(std::array<uint32_t,8>& state,const uint8_t* block) {
    uint32_t schedule[64];
    for(unsigned i=0;i<16;++i){const uint8_t* p=block+i*4;schedule[i]=(uint32_t(p[0])<<24)|(uint32_t(p[1])<<16)|(uint32_t(p[2])<<8)|p[3];}
    for(unsigned i=16;i<64;++i){uint32_t x=schedule[i-15],y=schedule[i-2];schedule[i]=schedule[i-16]+(rotate(x,7)^rotate(x,18)^(x>>3))+schedule[i-7]+(rotate(y,17)^rotate(y,19)^(y>>10));}
    auto work=state;
    for(unsigned i=0;i<64;++i){uint32_t a=work[0],b=work[1],c=work[2],e=work[4],f=work[5],g=work[6];
        uint32_t first=work[7]+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+RoundConstants[i]+schedule[i];
        uint32_t second=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));
        for(unsigned j=7;j>0;--j)work[j]=work[j-1];work[4]+=first;work[0]=first+second;
    }
    for(unsigned i=0;i<8;++i)state[i]+=work[i];
}
uint16_t u16(const uint8_t* p){return uint16_t(p[0])|(uint16_t(p[1])<<8);}
uint32_t u32(const uint8_t* p){return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);}
bool powerOfTwo(uint32_t x){return x && !(x&(x-1));}
bool fail(std::string& error,const char* message){error=message;return false;}

#ifdef _WIN32
struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h=INVALID_HANDLE_VALUE):value(h){}
    ~Handle(){if(value!=INVALID_HANDLE_VALUE && value!=nullptr)CloseHandle(value);}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
    Handle(Handle&& other) noexcept:value(other.value){other.value=INVALID_HANDLE_VALUE;}
    Handle& operator=(Handle&& other) noexcept {if(this!=&other){if(value!=INVALID_HANDLE_VALUE && value!=nullptr)CloseHandle(value);value=other.value;other.value=INVALID_HANDLE_VALUE;}return *this;}
    explicit operator bool()const{return value!=INVALID_HANDLE_VALUE && value!=nullptr;}
};
struct LocalMemory {void* p=nullptr;~LocalMemory(){if(p)LocalFree(p);}};
std::wstring wide(const std::string& input){
    if(input.empty() || input.size()>32760 || input.find('\0')!=std::string::npos)return {};
    int count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),nullptr,0);if(count<=0)return {};
    std::wstring out(count,L'\0');if(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),out.data(),count)!=count)return {};return out;
}
std::string utf8(const std::wstring& input){
    int count=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),nullptr,0,nullptr,nullptr);if(count<=0)return {};
    std::string out(count,'\0');if(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,input.data(),static_cast<int>(input.size()),out.data(),count,nullptr,nullptr)!=count)return {};return out;
}
bool winFail(std::string& error,const char* message,DWORD code=GetLastError()){error=std::string(message)+" (Windows error "+std::to_string(code)+")";return false;}
struct PrivateSecurity {
    std::vector<uint8_t> tokenData;
    LocalMemory descriptor;
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),nullptr,FALSE};
    PSID user=nullptr;
    bool initialize(std::string& error){
        HANDLE raw=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))return winFail(error,"Cannot inspect current user for helper cache");Handle token(raw);
        DWORD size=0;GetTokenInformation(token.value,TokenUser,nullptr,0,&size);
        if(!size || size>65536)return fail(error,"Current-user token size is invalid");tokenData.resize(size);
        if(!GetTokenInformation(token.value,TokenUser,tokenData.data(),size,&size))return winFail(error,"Cannot read helper cache user identity");
        user=reinterpret_cast<TOKEN_USER*>(tokenData.data())->User.Sid;
        LPWSTR text=nullptr;if(!ConvertSidToStringSidW(user,&text))return winFail(error,"Cannot format helper cache user identity");LocalMemory sidText;sidText.p=text;
        std::wstring sddl=L"O:"+std::wstring(text)+L"D:P(A;OICI;FA;;;"+text+L")(A;OICI;FA;;;SY)";
        PSECURITY_DESCRIPTOR sd=nullptr;if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd,nullptr))return winFail(error,"Cannot construct private helper cache permissions");
        descriptor.p=sd;attributes.lpSecurityDescriptor=sd;return true;
    }
};
bool localPath(const std::wstring& path,std::vector<std::wstring>& components,std::string& error){
    if(path.size()<4 || path.size()>30000 || path[1]!=L':' || (path[2]!=L'\\' && path[2]!=L'/') || !((path[0]>=L'A'&&path[0]<=L'Z')||(path[0]>=L'a'&&path[0]<=L'z')))
        return fail(error,"Helper cache must be an absolute local drive directory");
    std::wstring root=path.substr(0,3);root[2]=L'\\';
    const UINT kind=GetDriveTypeW(root.c_str());if(kind!=DRIVE_FIXED)return fail(error,"Helper cache must reside on a local fixed drive");
    components.push_back(root);
    std::wstring prefix=root;
    for(size_t first=3;first<path.size();){size_t end=path.find_first_of(L"\\/",first);if(end==std::wstring::npos)end=path.size();
        std::wstring item=path.substr(first,end-first);
        if(item.empty() || item==L"." || item==L".." || item.back()==L'.' || item.back()==L' ' || item.find_first_of(L":*?\"<>|")!=std::wstring::npos)return fail(error,"Helper cache directory contains an unsafe path component");
        if(prefix.back()!=L'\\')prefix+=L'\\';prefix+=item;components.push_back(prefix);first=end+1;
    }
    if(components.size()<2)return fail(error,"Helper cache cannot be a drive root");return true;
}
bool lockPrivateDirectory(const std::wstring& path,PrivateSecurity& security,std::vector<Handle>& locks,std::string& error,bool restrictPermissions=true){
    std::vector<std::wstring> components;if(!localPath(path,components,error))return false;
    for(size_t i=0;i<components.size();++i){bool last=i+1==components.size();
        if(last && !CreateDirectoryW(components[i].c_str(),&security.attributes) && GetLastError()!=ERROR_ALREADY_EXISTS)return winFail(error,"Cannot create private helper cache directory");
        DWORD access=FILE_READ_ATTRIBUTES|(last?(READ_CONTROL|WRITE_DAC):0);
        Handle directory(CreateFileW(components[i].c_str(),access,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(!directory)return winFail(error,"Cannot lock helper cache directory ancestry");
        BY_HANDLE_FILE_INFORMATION info{};
        if(!GetFileInformationByHandle(directory.value,&info))return winFail(error,"Cannot inspect helper cache directory");
        if(!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) || (info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))return fail(error,"Helper cache directories cannot be reparse points");
        if(last){
            PSID owner=nullptr;PSECURITY_DESCRIPTOR sd=nullptr;DWORD rc=GetSecurityInfo(directory.value,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,&owner,nullptr,nullptr,nullptr,&sd);LocalMemory existing;existing.p=sd;
            if(rc!=ERROR_SUCCESS)return winFail(error,"Cannot inspect helper cache directory ownership",rc);
            if(!owner || !EqualSid(owner,security.user))return fail(error,"Existing helper cache directory is owned by another user");
            BOOL present=FALSE,defaulted=FALSE;PACL dacl=nullptr;
            if(!GetSecurityDescriptorDacl(security.descriptor.p,&present,&dacl,&defaulted) || !present || !dacl)return fail(error,"Private helper cache permission descriptor has no DACL");
            if(restrictPermissions){rc=SetSecurityInfo(directory.value,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,dacl,nullptr);
                if(rc!=ERROR_SUCCESS)return winFail(error,"Cannot restrict helper cache directory permissions",rc);}
        }
        locks.push_back(std::move(directory));
    }
    return true;
}
enum class CacheCheck {Missing,Matches,Different,Rejected};
CacheCheck checkCached(const std::wstring& filename,std::span<const uint8_t> expected,std::string& error){
    Handle file(CreateFileW(filename.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr));
    if(!file){if(GetLastError()==ERROR_FILE_NOT_FOUND)return CacheCheck::Missing;winFail(error,"Cannot read cached GameMaker helper");return CacheCheck::Rejected;}
    BY_HANDLE_FILE_INFORMATION info{};
    if(!GetFileInformationByHandle(file.value,&info)){winFail(error,"Cannot inspect cached GameMaker helper");return CacheCheck::Rejected;}
    if((info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) || info.nNumberOfLinks!=1){fail(error,"Cached helper must be a regular file with a single link");return CacheCheck::Rejected;}
    uint64_t size=(uint64_t(info.nFileSizeHigh)<<32)|info.nFileSizeLow;
    if(size!=expected.size())return CacheCheck::Different;
    std::vector<uint8_t> read(expected.size());size_t pos=0;
    while(pos<read.size()){DWORD wanted=static_cast<DWORD>(std::min<size_t>(1024*1024,read.size()-pos)),got=0;
        if(!ReadFile(file.value,read.data()+pos,wanted,&got,nullptr) || got!=wanted){winFail(error,"Cannot verify cached helper bytes");return CacheCheck::Rejected;}pos+=got;}
    return GameMakerHelperSha256(read)==GameMakerHelperSha256(expected)?CacheCheck::Matches:CacheCheck::Different;
}
#endif
}

std::string GameMakerHelperSha256(std::span<const uint8_t> bytes){
    std::array<uint32_t,8> state={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t position=0;while(bytes.size()-position>=64){compress(state,bytes.data()+position);position+=64;}
    std::array<uint8_t,128> tail{};size_t remaining=bytes.size()-position;if(remaining)std::memcpy(tail.data(),bytes.data()+position,remaining);tail[remaining]=0x80;
    size_t finalSize=remaining<56?64:128;uint64_t bits=uint64_t(bytes.size())*8;
    for(unsigned i=0;i<8;++i)tail[finalSize-1-i]=uint8_t(bits>>(i*8));compress(state,tail.data());if(finalSize==128)compress(state,tail.data()+64);
    static const char digits[]="0123456789abcdef";std::string result;result.reserve(64);
    for(uint32_t value:state)for(int shift=28;shift>=0;shift-=4)result.push_back(digits[(value>>shift)&15]);return result;
}

bool ValidateGameMakerHelperImage(std::span<const uint8_t> bytes,std::string& error){
    error.clear();if(bytes.size()<512 || bytes.size()>GameMakerHelperMaximumBytes)return fail(error,"Embedded GameMaker helper size is outside the admitted bounds");
    const uint8_t* data=bytes.data();
    if(data[0]!='M' || data[1]!='Z')return fail(error,"Embedded GameMaker helper has no DOS signature");
    uint32_t pe=u32(data+0x3c);if(pe<64 || pe>bytes.size()-24 || std::memcmp(data+pe,"PE\0\0",4)!=0)return fail(error,"Embedded GameMaker helper has invalid PE headers");
    if(u16(data+pe+4)!=0x8664)return fail(error,"Embedded GameMaker helper must target AMD64");
    uint16_t count=u16(data+pe+6),optional=u16(data+pe+20),flags=u16(data+pe+22);
    if(!count || count>96 || (flags&0x2002)!=0x2002 || optional<240)return fail(error,"Embedded GameMaker helper must be a bounded executable DLL");
    uint64_t opt=uint64_t(pe)+24,sectionTable=opt+optional,sectionEnd=sectionTable+uint64_t(count)*40;
    if(sectionEnd>bytes.size() || u16(data+opt)!=0x20b)return fail(error,"Embedded GameMaker helper optional headers are invalid");
    uint32_t entry=u32(data+opt+16),sectionAlignment=u32(data+opt+32),fileAlignment=u32(data+opt+36),imageSize=u32(data+opt+56),headers=u32(data+opt+60);
    if(!powerOfTwo(sectionAlignment) || !powerOfTwo(fileAlignment) || fileAlignment<512 || fileAlignment>65536 || sectionAlignment<fileAlignment || sectionAlignment<4096 || sectionAlignment>65536 || !imageSize || imageSize>128u*1024u*1024u || imageSize%sectionAlignment || headers<sectionEnd || headers>bytes.size() || headers%fileAlignment || headers>imageSize)
        return fail(error,"Embedded GameMaker helper image/section alignment is invalid");
    std::vector<std::pair<uint64_t,uint64_t>> fileRanges,virtualRanges;bool executableEntry=false;
    for(uint16_t i=0;i<count;++i){const uint8_t* s=data+sectionTable+uint64_t(i)*40;
        uint32_t virtualSize=u32(s+8),va=u32(s+12),rawSize=u32(s+16),raw=u32(s+20),characteristics=u32(s+36);uint64_t mapped=std::max(virtualSize,rawSize);
        if(va%sectionAlignment || va<headers || uint64_t(va)+mapped>imageSize)return fail(error,"Embedded GameMaker helper section escapes the mapped image");
        if(rawSize){if(raw<headers || raw%fileAlignment || rawSize%fileAlignment || uint64_t(raw)+rawSize>bytes.size())return fail(error,"Embedded GameMaker helper section escapes its file");fileRanges.emplace_back(raw,uint64_t(raw)+rawSize);}
        if(mapped)virtualRanges.emplace_back(va,uint64_t(va)+mapped);
        if(entry>=va && uint64_t(entry)-va<rawSize && (characteristics&0x20000000))executableEntry=true;
    }
    auto overlaps=[](auto& ranges){std::sort(ranges.begin(),ranges.end());for(size_t i=1;i<ranges.size();++i)if(ranges[i].first<ranges[i-1].second)return true;return false;};
    if(overlaps(fileRanges) || overlaps(virtualRanges))return fail(error,"Embedded GameMaker helper sections overlap");
    if(!executableEntry)return fail(error,"Embedded GameMaker helper entry is not backed by executable file bytes");
    return true;
}

bool ExtractGameMakerHelperBytes(std::span<const uint8_t> bytes,const std::string& cacheDirectory,std::string& outputPath,std::string& error){
    outputPath.clear();error.clear();if(!ValidateGameMakerHelperImage(bytes,error))return false;
#ifdef _WIN32
    try{
        std::wstring directory=wide(cacheDirectory);if(directory.empty())return fail(error,"Helper cache directory is not valid UTF-8");
        PrivateSecurity security;if(!security.initialize(error))return false;
        std::vector<Handle> directoryLocks;if(!lockPrivateDirectory(directory,security,directoryLocks,error))return false;
        if(directory.back()!=L'\\' && directory.back()!=L'/')directory+=L'\\';
        std::string digest=GameMakerHelperSha256(bytes);std::wstring filename=directory+L"GameMakerHelper-"+std::wstring(digest.begin(),digest.end())+L".dll";
        auto status=checkCached(filename,bytes,error);if(status==CacheCheck::Rejected)return false;
        if(status!=CacheCheck::Matches){
            static std::atomic<uint64_t> sequence{0};std::wstring temporary;Handle staging;
            for(unsigned attempt=0;attempt<32;++attempt){temporary=filename+L".tmp-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L"-"+std::to_wstring(sequence.fetch_add(1));
                staging=Handle(CreateFileW(temporary.c_str(),GENERIC_WRITE,0,&security.attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
                if(staging)break;if(GetLastError()!=ERROR_FILE_EXISTS && GetLastError()!=ERROR_ALREADY_EXISTS)return winFail(error,"Cannot create helper staging file");}
            if(!staging)return fail(error,"Could not reserve a unique helper staging filename");
            bool written=true;size_t pos=0;
            while(pos<bytes.size()){DWORD wanted=static_cast<DWORD>(std::min<size_t>(1024*1024,bytes.size()-pos)),done=0;if(!WriteFile(staging.value,bytes.data()+pos,wanted,&done,nullptr) || done!=wanted){written=false;winFail(error,"Cannot write embedded helper bytes");break;}pos+=done;}
            if(written && !FlushFileBuffers(staging.value)){written=false;winFail(error,"Cannot flush embedded helper bytes");}
            staging=Handle();
            if(!written){DeleteFileW(temporary.c_str());return false;}
            if(checkCached(temporary,bytes,error)!=CacheCheck::Matches){DeleteFileW(temporary.c_str());if(error.empty())error="Staged helper failed SHA-256 verification";return false;}
            // Same-directory rename atomically installs the fully flushed, verified resource.
            if(!MoveFileExW(temporary.c_str(),filename.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){
                DWORD moveError=GetLastError();DeleteFileW(temporary.c_str());
                // Another app instance may have installed the identical digest meanwhile.
                if(checkCached(filename,bytes,error)!=CacheCheck::Matches)return winFail(error,"Cannot atomically install embedded helper",moveError);
            }
        }
        if(checkCached(filename,bytes,error)!=CacheCheck::Matches){if(error.empty())error="Installed helper failed SHA-256 verification";return false;}
        outputPath=utf8(filename);if(outputPath.empty())return fail(error,"Extracted helper path could not be encoded as UTF-8");error.clear();return true;
    }catch(const std::bad_alloc&){return fail(error,"Helper extraction allocation failed");}
#else
    (void)cacheDirectory;return fail(error,"GameMaker helper extraction requires Windows");
#endif
}

bool ExtractEmbeddedGameMakerHelper(std::string& outputPath,std::string& error){
    outputPath.clear();error.clear();
#ifdef _WIN32
    HMODULE module=GetModuleHandleW(nullptr);HRSRC resource=FindResourceW(module,MAKEINTRESOURCEW(GameMakerHelperResourceId),MAKEINTRESOURCEW(10));
    if(!resource)return fail(error,"This DisasmStudio build has no embedded GameMaker helper resource");
    DWORD size=SizeofResource(module,resource);if(!size || size>GameMakerHelperMaximumBytes)return fail(error,"Embedded GameMaker helper resource exceeds its admitted size");
    HGLOBAL loaded=LoadResource(module,resource);const auto* data=static_cast<const uint8_t*>(loaded?LockResource(loaded):nullptr);if(!data)return winFail(error,"Cannot read embedded GameMaker helper resource");
    std::string validation;if(!ValidateGameMakerHelperImage({data,size},validation)){error=std::move(validation);return false;}
    wchar_t local[MAX_PATH]{};if(FAILED(SHGetFolderPathW(nullptr,CSIDL_LOCAL_APPDATA,nullptr,SHGFP_TYPE_CURRENT,local)))return fail(error,"Cannot locate per-user Local AppData for the helper cache");
    // Create only the two fixed application-owned directories below the OS-known location.
    PrivateSecurity security;if(!security.initialize(error))return false;std::vector<Handle> ancestry;
    std::wstring app=std::wstring(local)+L"\\DisasmStudio";
    // Other DisasmStudio caches may already use this parent; leave their DACL unchanged.
    if(!lockPrivateDirectory(app,security,ancestry,error,false))return false;
    return ExtractGameMakerHelperBytes({data,size},utf8(app+L"\\GameMakerHelper"),outputPath,error);
#else
    return fail(error,"Embedded GameMaker helper extraction requires Windows");
#endif
}
} // namespace ds
