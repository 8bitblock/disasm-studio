//
// function_namer_test.cpp
// Off-target unit test for the PURE part of the heuristic function namer
// (src/Core/FunctionNamer.cpp): GuessFromEvidence() and ToSnakeIdentifier().
// These take a small FuncEvidence struct (no disassembler) so they test cleanly.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\function_namer_test.cpp src\Core\FunctionNamer.cpp src\Core\BinaryFile.cpp
//   .\function_namer_test.exe
//
#include "Core/FunctionNamer.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)
#define CHECK_EQ(a, b) do { auto _a = (a); auto _b = (b); if (!(_a == _b)) { \
    std::printf("FAIL %s:%d  %s == %s   got \"%s\" want \"%s\"\n", \
        __FILE__, __LINE__, #a, #b, std::string(_a).c_str(), std::string(_b).c_str()); ++g_fail; } } while (0)

// Build evidence whose only signal is the set of called APIs.
static FuncEvidence apis(std::vector<std::string> a, int instr = 30, int calls = 3) {
    FuncEvidence e; e.apis = std::move(a); e.instrCount = instr; e.callCount = calls; return e;
}

int main() {
    // ---- ToSnakeIdentifier ------------------------------------------------
    CHECK_EQ(ToSnakeIdentifier("CreateFileW"),  "create_file");
    CHECK_EQ(ToSnakeIdentifier("ReadFile"),     "read_file");
    CHECK_EQ(ToSnakeIdentifier("GetTickCount"), "get_tick_count");
    CHECK_EQ(ToSnakeIdentifier("GetProcAddress"), "get_proc_address");
    CHECK_EQ(ToSnakeIdentifier("RtlZeroMemory"), "rtl_zero_memory");
    CHECK_EQ(ToSnakeIdentifier("_malloc"),      "malloc");
    CHECK_EQ(ToSnakeIdentifier("VirtualAllocEx"), "virtual_alloc_ex");
    CHECK_EQ(ToSnakeIdentifier("KERNEL32.CreateFileW"), "create_file");
    CHECK_EQ(ToSnakeIdentifier("__imp_CreateFileW@16"), "create_file");
    CHECK_EQ(ToSnakeIdentifier("__imp__CreateFileW@16"), "create_file");
    CHECK_EQ(ToSnakeIdentifier("@CreateFileW@16"), "create_file");
    CHECK_EQ(ToSnakeIdentifier("__imp_@CreateFileW@16"), "create_file");
    CHECK_EQ(ToSnakeIdentifier("operator new"), "operator_new");
    CHECK_EQ(ToSnakeIdentifier("123Api"), "fn_123_api");
    CHECK(ToSnakeIdentifier("#12").empty());

    // ---- entry / thunk / stubs (highest priority) -------------------------
    { FuncEvidence e; e.isEntry = true; e.apis = {"ExitProcess"};
      CHECK_EQ(GuessFromEvidence(e).name, "start"); }
    { FuncEvidence e; e.isThunk = true; e.thunkApi = "CreateFileW";
      auto g = GuessFromEvidence(e); CHECK_EQ(g.name, "j_CreateFileW"); CHECK(g.guessed); }
    { FuncEvidence e; e.isThunk = true; e.thunkApi = "__imp_CreateFileW@16";
      CHECK_EQ(GuessFromEvidence(e).name, "j_CreateFileW"); }
    for (const char* decorated : {
             "__imp__CreateFileW@16", "@CreateFileW@16", "__imp_@CreateFileW@16" }) {
        FuncEvidence e; e.isThunk = true; e.thunkApi = decorated;
        CHECK_EQ(GuessFromEvidence(e).name, "j_CreateFileW");
    }
    { FuncEvidence e; e.isThunk = true; e.thunkApi = "#12";
      CHECK(!GuessFromEvidence(e).guessed); }
    { FuncEvidence e; e.isThunk = true; e.thunkApi = "";   // jmp to a local sub -> no guess
      CHECK(!GuessFromEvidence(e).guessed); }
    { FuncEvidence e; e.retOnly = true; e.callCount = 0; e.instrCount = 1;
      CHECK_EQ(GuessFromEvidence(e).name, "nullsub"); }
    { FuncEvidence e; e.retZero = true; e.callCount = 0; e.instrCount = 2;
      CHECK_EQ(GuessFromEvidence(e).name, "ret_zero"); }

    // Bare scalar checks have exact storage-oriented names. In particular,
    // equals-one and nonzero are different predicates, and no Boolean type or
    // Zen-ball meaning follows from seeing the constants 0/1.
    {
        FuncEvidence e; e.instrCount = 4;
        e.scalarFunction = {ScalarFunctionKind::IsOne, "field_1c", "[rcx+0x1c]", 32, 0x401000, true};
        auto guess = GuessFromEvidence(e);
        CHECK_EQ(guess.name, "is_field_1c_one");
        CHECK(guess.reason.find("32-bit [rcx+0x1c] == 1") != std::string::npos);
        CHECK(guess.reason.find("returns 0 otherwise") != std::string::npos);
        CHECK(guess.reason.find("application meaning remains unknown") != std::string::npos);
        CHECK(guess.name.find("zen") == std::string::npos);
        e.scalarFunction.kind = ScalarFunctionKind::IsNonzero;
        CHECK_EQ(GuessFromEvidence(e).name, "is_field_1c_nonzero");
        e.scalarFunction.kind = ScalarFunctionKind::IsNotOne;
        CHECK_EQ(GuessFromEvidence(e).name, "is_field_1c_not_one");
        e.scalarFunction.kind = ScalarFunctionKind::IsZero;
        CHECK_EQ(GuessFromEvidence(e).name, "is_field_1c_zero");
        e.scalarFunction.kind = ScalarFunctionKind::Getter;
        CHECK_EQ(GuessFromEvidence(e).name, "read_field_1c");
        e.scalarFunction.kind = ScalarFunctionKind::SetOne;
        CHECK_EQ(GuessFromEvidence(e).name, "write_field_1c_one");
        e.scalarFunction.kind = ScalarFunctionKind::SetZero;
        CHECK_EQ(GuessFromEvidence(e).name, "write_field_1c_zero");
        e.bodySampled = true; CHECK(!GuessFromEvidence(e).guessed);
        e.bodySampled = false; e.callCount = 1; CHECK(!GuessFromEvidence(e).guessed);
        e.callCount = 0; e.scalarFunction.complete = false; CHECK(!GuessFromEvidence(e).guessed);
        e.scalarFunction.complete = true; e.scalarFunction.widthBits = 0; CHECK(!GuessFromEvidence(e).guessed);
        e.scalarFunction.widthBits = 32; e.strings = {"IsZenBall"};
        CHECK_EQ(GuessFromEvidence(e).name, "IsZenBall"); // real identifier evidence keeps priority
        e.strings = {"zen ball"};
        CHECK_EQ(GuessFromEvidence(e).name, "write_field_1c_zero"); // nearby text is not an exact field binding
    }

    // ---- semantic names from API sets -------------------------------------
    CHECK_EQ(GuessFromEvidence(apis({"CreateFileW","ReadFile","CloseHandle"})).name,  "read_file");
    CHECK_EQ(GuessFromEvidence(apis({"CreateFileW","WriteFile","CloseHandle"})).name, "write_file");
    CHECK_EQ(GuessFromEvidence(apis({"CreateFileW","CloseHandle"})).name,             "open_file");
    CHECK_EQ(GuessFromEvidence(apis({"DeleteFileW"})).name,                           "delete_file");
    CHECK_EQ(GuessFromEvidence(apis({"RegOpenKeyExW","RegQueryValueExW"})).name,      "read_registry");
    CHECK_EQ(GuessFromEvidence(apis({"RegCreateKeyExW","RegSetValueExW"})).name,      "write_registry");
    CHECK_EQ(GuessFromEvidence(apis({"socket","connect","send"})).name,              "net_send");
    CHECK_EQ(GuessFromEvidence(apis({"socket","connect","recv"})).name,              "net_recv");
    CHECK_EQ(GuessFromEvidence(apis({"WSAStartup","socket","bind","listen"})).name,  "socket_setup");
    CHECK_EQ(GuessFromEvidence(apis({"VirtualAllocEx","WriteProcessMemory","CreateRemoteThread"})).name, "inject_code");
    CHECK_EQ(GuessFromEvidence(apis({"CreateRemoteThread"})).name,                    "inject_thread");
    CHECK_EQ(GuessFromEvidence(apis({"VirtualAlloc","VirtualProtect"})).name,         "allocate_protected_memory");
    CHECK_EQ(GuessFromEvidence(apis({"CreateProcessW"})).name,                        "launch_process");
    CHECK_EQ(GuessFromEvidence(apis({"LoadLibraryA","GetProcAddress"})).name,         "resolve_imports");
    CHECK_EQ(GuessFromEvidence(apis({"CryptEncrypt"})).name,                          "encrypt_data");
    CHECK_EQ(GuessFromEvidence(apis({"URLDownloadToFileW"})).name,                    "download_file");
    CHECK_EQ(GuessFromEvidence(apis({"IsDebuggerPresent"})).name,                     "check_debugger");
    CHECK_EQ(GuessFromEvidence(apis({"ExitProcess"})).name,                           "exit_process");

    // Generic classification uses exact, normalized API families too. Preserve
    // recognized Win32 variants/CRT decorations without guessing vendor exports
    // merely because their names contain an operation's spelling.
    for (const char* name : {"MyReadFile", "ReadFileFake", "VirtualAllocLog",
             "CreateProcessData", "strcmpIgnoreSuffix", "MyCryptHashDataHelper",
             "RegOpenKeyExWrapper", "SendMessageW", "ConnectNamedPipe",
             "Get_Proc_Address", "memcpy_checked_by_vendor"}) {
        CHECK(!GuessFromEvidence(apis({name}, 80, 1)).guessed);
    }
    CHECK_EQ(GuessFromEvidence(apis({"vendor.ReadFileFake"}, 8, 1)).name, "read_file_fake");
    CHECK_EQ(GuessFromEvidence(apis({"WS2_32.__imp__send@16"})).name, "net_send");
    CHECK_EQ(GuessFromEvidence(apis({"kernel32.dll!__imp__ReadFile@20"})).name, "read_file");
    CHECK_EQ(GuessFromEvidence(apis({"__imp__snprintf_s"})).name, "format_string");
    CHECK_EQ(GuessFromEvidence(apis({"ReadFileEx", "WriteFileGather"})).name, "read_write_file");
    CHECK_EQ(GuessFromEvidence(apis({"ntdll.NtReadFile", "ntdll.NtWriteFile"})).name, "read_write_file");
    CHECK_EQ(GuessFromEvidence(apis({"RegQueryValueExW", "RegSetValueExW"})).name, "read_write_registry");
    CHECK_EQ(GuessFromEvidence(apis({"CreateToolhelp32Snapshot", "Module32FirstW"})).name, "enumerate_modules");
    CHECK_EQ(GuessFromEvidence(apis({"CreateToolhelp32Snapshot", "Thread32First"})).name, "enumerate_threads");
    CHECK_EQ(GuessFromEvidence(apis({"CreateToolhelp32Snapshot"})).name, "create_system_snapshot");
    CHECK_EQ(GuessFromEvidence(apis({"OpenProcessToken"})).name, "open_access_token");
    CHECK_EQ(GuessFromEvidence(apis({"CreateFileMappingW", "MapViewOfFile"})).name, "map_memory");
    CHECK_EQ(GuessFromEvidence(apis({"read", "write"})).name, "read_write_descriptor");
    CHECK_EQ(GuessFromEvidence(apis({"pread64"})).name, "read_descriptor");
    CHECK_EQ(GuessFromEvidence(apis({"pwritev"})).name, "write_descriptor");
    CHECK_EQ(GuessFromEvidence(apis({"dlopen", "dlsym"})).name, "resolve_imports");
    CHECK_EQ(GuessFromEvidence(apis({"printf"})).name, "print_output");
    CHECK_EQ(GuessFromEvidence(apis({"mmap"})).name, "map_memory");
    CHECK_EQ(GuessFromEvidence(apis({"EVP_DigestUpdate"})).name, "hash_data");
    {
        FuncEvidence e = apis({"InternetGetConnectedState"}, 4, 1);
        e.connectivityResultReturned = true; e.bodySampled = true;
        CHECK(!GuessFromEvidence(e).guessed); // omitted work can invalidate a narrow wrapper
        e = {}; e.retZero = true; e.bodySampled = true;
        CHECK(!GuessFromEvidence(e).guessed);
    }

    // Connectivity predicates earn the analyst-facing WifiCheck name only when
    // the function immediately returns their result or branches on it. Merely
    // mentioning a connectivity-related API is not enough.
    {
        FuncEvidence e = apis({"InternetGetConnectedState"}, /*instr*/3, /*calls*/1);
        e.connectivityResultReturned = true;
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed); CHECK_EQ(g.name, "WifiCheck");
        CHECK(g.reason.find("InternetGetConnectedState") != std::string::npos);
        CHECK(g.reason.find("connectivity result") != std::string::npos);
    }
    {
        FuncEvidence e = apis({"InternetCheckConnectionW"}, /*instr*/6, /*calls*/1);
        e.connectivityResultChecked = true;
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed); CHECK_EQ(g.name, "WifiCheck");
        CHECK(g.reason.find("InternetCheckConnectionW") != std::string::npos);
        CHECK(g.reason.find("connectivity result") != std::string::npos);
    }
    {
        FuncEvidence e = apis({"InternetGetConnectedState"}, /*instr*/6, /*calls*/1);
        CHECK(GuessFromEvidence(e).name != "WifiCheck"); // result is never consumed
    }
    {
        FuncEvidence e = apis(
            {"InternetGetConnectedState", "CreateFileW", "ReadFile"},
            /*instr*/18, /*calls*/3);
        e.connectivityResultChecked = true;
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed);
        CHECK_EQ(g.name, "read_file"); // broader file worker, not a dedicated connectivity predicate
    }
    for (const char* decorated : {
             "__imp__InternetGetConnectedState@8",
             "@InternetGetConnectedState@8",
             "__imp_@InternetGetConnectedState@8" }) {
        FuncEvidence e = apis({decorated}, /*instr*/4, /*calls*/1);
        e.connectivityResultReturned = true;
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed);
        CHECK_EQ(g.name, "WifiCheck");
    }
    {
        FuncEvidence e = apis({"InternetGetConnectedState", "send"}, /*instr*/12, /*calls*/2);
        e.connectivityResultChecked = true;
        CHECK(GuessFromEvidence(e).name != "WifiCheck"); // transport work vetoes a predicate wrapper
    }
    {
        FuncEvidence e = apis({"WlanQueryInterface"}, /*instr*/6, /*calls*/1);
        e.connectivityResultChecked = true;
        CHECK(GuessFromEvidence(e).name != "WifiCheck"); // query class is unknown
    }
    {
        FuncEvidence e = apis({"MyInternetGetConnectedStateHelper"}, /*instr*/6, /*calls*/1);
        e.connectivityResultChecked = true;
        CHECK(GuessFromEvidence(e).name != "WifiCheck"); // API matching is exact, never substring based
    }
    {
        FuncEvidence e = apis({"InternetGetConnectedState"}, /*instr*/97, /*calls*/1);
        e.connectivityResultReturned = true;
        CHECK(GuessFromEvidence(e).name != "WifiCheck"); // bounded wrapper policy
    }
    {
        FuncEvidence e = apis({"InternetGetConnectedState"}, /*instr*/12, /*calls*/5);
        e.connectivityResultReturned = true;
        CHECK(GuessFromEvidence(e).name != "WifiCheck"); // too many calls for a predicate wrapper
    }

    // ---- contextual intent + operation names -----------------------------
    // A compound analyst-facing name requires independent subject and operation
    // evidence.  API result-use records distinguish an operation's status check
    // from a comparator/verifier result that actually controls a decision.
    {
        FuncEvidence e = apis(
            {"CryptCreateHash", "CryptHashData", "CryptGetHashParam"},
            /*instr*/36, /*calls*/3);
        e.strings = {"license key", "activation code"};
        e.apiResultUses.push_back({"CryptHashData", true, false});
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed);
        CHECK_EQ(g.name, "licenseHashing");
        CHECK(!g.reason.empty());
    }
    {
        FuncEvidence e = apis(
            {"CryptCreateHash", "CryptHashData", "CryptGetHashParam", "memcmp"},
            /*instr*/48, /*calls*/4);
        e.strings = {"license key", "invalid license"};
        e.apiResultUses.push_back({"CryptHashData", true, false}); // API success only
        e.apiResultUses.push_back({"memcmp", true, false});        // decision predicate
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed);
        CHECK_EQ(g.name, "licenseValidation");
        CHECK(!g.reason.empty());
    }
    {
        FuncEvidence e = apis(
            {"CryptCreateHash", "CryptHashData", "CryptGetHashParam", "memcmp"},
            /*instr*/42, /*calls*/4);
        e.strings = {"license key"};
        e.apiResultUses.push_back({"memcmp", false, true, false});
        CHECK_EQ(GuessFromEvidence(e).name, "licenseHashing"); // raw tri-state return is not Boolean
        e.apiResultUses.back().normalizedReturned = true;
        CHECK_EQ(GuessFromEvidence(e).name, "licenseValidation");
    }
    {
        FuncEvidence e = apis(
            {"BCryptCreateHash", "BCryptHashData", "BCryptFinishHash"},
            /*instr*/34, /*calls*/3);
        e.strings = {"password hash", "enter password"};
        e.apiResultUses.push_back({"BCryptFinishHash", true, false});
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed);
        CHECK_EQ(g.name, "passwordHashing");
    }
    {
        FuncEvidence e = apis(
            {"BCryptGenRandom", "BCryptCreateHash", "BCryptHashData", "BCryptFinishHash"},
            /*instr*/42, /*calls*/4);
        e.strings = {"password hash"};
        CHECK_EQ(GuessFromEvidence(e).name, "passwordHashing"); // RNG is compatible salt support
    }
    {
        FuncEvidence e = apis({"CryptDecrypt"}, /*instr*/20, /*calls*/1);
        e.strings = {"encrypted config", "settings.ini"};
        e.apiResultUses.push_back({"CryptDecrypt", true, false});
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed);
        CHECK_EQ(g.name, "configDecryption");
    }
    {
        FuncEvidence e = apis(
            {"EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex"},
            /*instr*/30, /*calls*/3);
        e.strings = {"encrypted config"};
        CHECK_EQ(GuessFromEvidence(e).name, "configDecryption");
    }
    {
        FuncEvidence e = apis({"RtlDecompressBuffer"}, /*instr*/22, /*calls*/1);
        e.strings = {"compressed payload"};
        e.apiResultUses.push_back({"RtlDecompressBuffer", true, false});
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed);
        CHECK_EQ(g.name, "payloadDecompression");
    }
    {
        FuncEvidence e = apis({"BCryptGenRandom"}, /*instr*/18, /*calls*/1);
        e.strings = {"authentication token"};
        e.apiResultUses.push_back({"BCryptGenRandom", true, false});
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed);
        CHECK_EQ(g.name, "tokenGeneration");
    }
    {
        FuncEvidence e = apis({"WinVerifyTrust"}, /*instr*/18, /*calls*/1);
        e.strings = {"integrity check"};
        e.apiResultUses.push_back({"WinVerifyTrust", true, false});
        auto g = GuessFromEvidence(e);
        CHECK(g.guessed);
        CHECK_EQ(g.name, "integrityVerification");
    }

    // Compound guesses stay conservative: neither half of the evidence is
    // sufficient by itself, matching is exact, and broad/ambiguous workers
    // retain a generic mechanical name.
    {
        FuncEvidence e = apis(
            {"CryptCreateHash", "CryptHashData", "CryptGetHashParam"},
            /*instr*/30, /*calls*/3);
        CHECK_EQ(GuessFromEvidence(e).name, "hash_data"); // operation, no subject
    }
    {
        FuncEvidence e;
        e.instrCount = 16;
        e.strings = {"license key", "activation code"};
        CHECK(!GuessFromEvidence(e).guessed); // subject, no operation
    }
    {
        FuncEvidence e = apis(
            {"CryptCreateHash", "CryptHashData", "CryptGetHashParam"},
            /*instr*/32, /*calls*/3);
        e.strings = {"Software License Agreement"};
        CHECK_EQ(GuessFromEvidence(e).name, "hash_data"); // legal prose is not key material
    }
    {
        FuncEvidence e = apis({"MyCryptHashDataHelper"}, /*instr*/12, /*calls*/1);
        e.strings = {"license key"};
        auto g = GuessFromEvidence(e);
        CHECK(g.name != "licenseHashing"); // exact API catalog, never substring matching
        CHECK(g.name != "licenseValidation");
    }
    {
        FuncEvidence e = apis({"CryptHashData"}, /*instr*/14, /*calls*/1);
        e.strings = {"license key"};
        e.apiResultUses.push_back({"CryptHashData", true, false});
        CHECK_EQ(GuessFromEvidence(e).name, "hash_data"); // incomplete hash pipeline
    }
    {
        FuncEvidence e = apis({"BCryptOpenAlgorithmProvider"}, /*instr*/12, /*calls*/1);
        e.strings = {"license key"};
        CHECK(GuessFromEvidence(e).name != "licenseHashing"); // setup alone is not hashing
    }
    {
        FuncEvidence e = apis(
            {"CryptGetHashParam", "CryptHashData", "CryptCreateHash"},
            /*instr*/24, /*calls*/3);
        e.strings = {"license key"};
        CHECK_EQ(GuessFromEvidence(e).name, "hash_data"); // phases in reverse are not a workflow
    }
    {
        FuncEvidence e = apis({"EVP_DecryptInit_ex"}, /*instr*/12, /*calls*/1);
        e.strings = {"encrypted config"};
        CHECK(GuessFromEvidence(e).name != "configDecryption"); // initialization processes no data
    }
    {
        FuncEvidence e = apis({"CryptDecrypt"}, /*instr*/12, /*calls*/1);
        e.strings = {"settings.initial"};
        CHECK_EQ(GuessFromEvidence(e).name, "decrypt_data"); // .ini must be a bounded extension
    }
    {
        FuncEvidence e = apis({"BCryptGenRandom"}, /*instr*/12, /*calls*/1);
        e.strings = {"password"};
        CHECK(GuessFromEvidence(e).name != "passwordGeneration"); // RNG may only be salt
    }
    {
        FuncEvidence e = apis(
            {"CryptCreateHash", "CryptHashData", "CryptGetHashParam"},
            /*instr*/28, /*calls*/3);
        e.strings = {"license"};
        CHECK_EQ(GuessFromEvidence(e).name, "hash_data"); // bare legal/product word is ambiguous
    }
    {
        FuncEvidence e = apis({"memcmp"}, /*instr*/16, /*calls*/1);
        e.strings = {"license key", "invalid license"};
        CHECK_EQ(GuessFromEvidence(e).name, "compare_buffer"); // comparator result unchecked
    }
    {
        FuncEvidence e = apis(
            {"CryptCreateHash", "CryptHashData", "CryptGetHashParam"},
            /*instr*/34, /*calls*/3);
        e.strings = {"license key", "password hash"};
        CHECK_EQ(GuessFromEvidence(e).name, "hash_data"); // conflicting subjects
    }
    {
        FuncEvidence e = apis(
            {"CryptCreateHash", "CryptHashData", "CryptGetHashParam", "send"},
            /*instr*/60, /*calls*/4);
        e.strings = {"license key"};
        auto g = GuessFromEvidence(e);
        CHECK(g.name != "licenseHashing"); // broader network worker vetoes the narrow intent
        CHECK(g.name != "licenseValidation");
    }
    {
        FuncEvidence e = apis({"WinVerifyTrust"}, /*instr*/16, /*calls*/1);
        e.strings = {"license key"};
        e.apiResultUses.push_back({"WinVerifyTrust", true, false});
        CHECK(GuessFromEvidence(e).name != "licenseValidation"); // publisher trust is not licensing
    }

    // "SendMessageW" must NOT be mistaken for a network send.
    CHECK(GuessFromEvidence(apis({"SendMessageW"})).name != "net_send");
    // Substring matching `free` used to mislabel both as free_buffer.
    CHECK_EQ(GuessFromEvidence(apis({"FreeLibrary"}, 5, 1)).name, "free_library");
    CHECK_EQ(GuessFromEvidence(apis({"VirtualFree"}, 5, 1)).name, "virtual_free");

    // ---- single-API thin wrapper ------------------------------------------
    { auto g = GuessFromEvidence(apis({"GetTickCount"}, /*instr*/5, /*calls*/1));
      CHECK_EQ(g.name, "get_tick_count"); CHECK(g.guessed); }
    // ...but a big function with one unrecognized call is not a "wrapper".
    CHECK(!GuessFromEvidence(apis({"GetTickCount"}, /*instr*/80, /*calls*/1)).guessed);

    // ---- string-derived name (embedded identifier) ------------------------
    { FuncEvidence e; e.instrCount = 20; e.strings = {"OpenConfig"};
      auto g = GuessFromEvidence(e); CHECK_EQ(g.name, "OpenConfig"); CHECK(g.guessed); }
    { FuncEvidence e; e.instrCount = 20; e.strings = {"access_denied"};
      CHECK_EQ(GuessFromEvidence(e).name, "access_denied"); }
    { FuncEvidence e; e.instrCount = 20; e.strings = {"password", "success", "error"};
      CHECK(!GuessFromEvidence(e).guessed); }
    { FuncEvidence e; e.instrCount = 20; e.strings = {"sub_DEADBEEF"};
      CHECK(!GuessFromEvidence(e).guessed); }
    { FuncEvidence e; e.instrCount = 20; e.strings = {"%s: error %d\n", "ok"};  // not identifier-like
      CHECK(!GuessFromEvidence(e).guessed); }

    // String-linked operation names require both a typed stored action and a
    // short, same-block reference. Stronger established evidence still wins.
    {
        FuncEvidence e; e.instrCount = 8; e.strings = {"added!"};
        CHECK(!GuessFromEvidence(e).guessed);
        e.stringActions.push_back({"added!", 0x1234, 0x1238, true, false, true});
        auto named = GuessFromEvidence(e);
        CHECK_EQ(named.name, "add_value_candidate"); CHECK(named.guessed);
        CHECK(named.reason.find("0x1234") != std::string::npos);
        CHECK(named.reason.find("unproved") != std::string::npos);
        e.stringActions[0].text = "point added!";
        CHECK_EQ(GuessFromEvidence(e).name, "add_points_candidate");
        e.stringActions[0].sameBlock = false;
        CHECK(!GuessFromEvidence(e).guessed);
        e.stringActions[0].sameBlock = true;
        e.stringActions[0].text = "point was not added!";
        CHECK(!GuessFromEvidence(e).guessed);
        e.stringActions[0].text = "added!";
        e.apis = {"ReadFile"}; e.callCount = 1;
        CHECK_EQ(GuessFromEvidence(e).name, "read_file");
        e.apis.clear(); e.strings = {"RealWorkerName"};
        CHECK_EQ(GuessFromEvidence(e).name, "RealWorkerName");
        e.strings.clear(); e.instrCount = 300;
        CHECK(!GuessFromEvidence(e).guessed);
        e.instrCount = 8;
        e.stringActions.push_back({"points removed!", 0x1240, 0x1248, false, true, true});
        CHECK(!GuessFromEvidence(e).guessed); // conflicting action messages
    }

    // ---- nothing to go on -> no guess -------------------------------------
    { FuncEvidence e; e.instrCount = 40; e.callCount = 0;
      CHECK(!GuessFromEvidence(e).guessed); }

    if (g_fail == 0) std::printf("function_namer_test: ALL PASS\n");
    else             std::printf("function_namer_test: %d FAIL\n", g_fail);
    return g_fail ? 1 : 0;
}
