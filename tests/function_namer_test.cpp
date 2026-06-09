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

    // ---- entry / thunk / stubs (highest priority) -------------------------
    { FuncEvidence e; e.isEntry = true; e.apis = {"ExitProcess"};
      CHECK_EQ(GuessFromEvidence(e).name, "start"); }
    { FuncEvidence e; e.isThunk = true; e.thunkApi = "CreateFileW";
      auto g = GuessFromEvidence(e); CHECK_EQ(g.name, "j_CreateFileW"); CHECK(g.guessed); }
    { FuncEvidence e; e.isThunk = true; e.thunkApi = "";   // jmp to a local sub -> no guess
      CHECK(!GuessFromEvidence(e).guessed); }
    { FuncEvidence e; e.retOnly = true; e.callCount = 0; e.instrCount = 1;
      CHECK_EQ(GuessFromEvidence(e).name, "nullsub"); }
    { FuncEvidence e; e.retZero = true; e.callCount = 0; e.instrCount = 2;
      CHECK_EQ(GuessFromEvidence(e).name, "ret_zero"); }

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
    CHECK_EQ(GuessFromEvidence(apis({"VirtualAlloc","VirtualProtect"})).name,         "alloc_exec_memory");
    CHECK_EQ(GuessFromEvidence(apis({"CreateProcessW"})).name,                        "launch_process");
    CHECK_EQ(GuessFromEvidence(apis({"LoadLibraryA","GetProcAddress"})).name,         "resolve_imports");
    CHECK_EQ(GuessFromEvidence(apis({"CryptEncrypt"})).name,                          "encrypt_data");
    CHECK_EQ(GuessFromEvidence(apis({"URLDownloadToFileW"})).name,                    "download_file");
    CHECK_EQ(GuessFromEvidence(apis({"IsDebuggerPresent"})).name,                     "check_debugger");
    CHECK_EQ(GuessFromEvidence(apis({"ExitProcess"})).name,                           "exit_process");

    // "SendMessageW" must NOT be mistaken for a network send.
    CHECK(GuessFromEvidence(apis({"SendMessageW"})).name != "net_send");

    // ---- single-API thin wrapper ------------------------------------------
    { auto g = GuessFromEvidence(apis({"GetTickCount"}, /*instr*/5, /*calls*/1));
      CHECK_EQ(g.name, "get_tick_count"); CHECK(g.guessed); }
    // ...but a big function with one unrecognized call is not a "wrapper".
    CHECK(!GuessFromEvidence(apis({"GetTickCount"}, /*instr*/80, /*calls*/1)).guessed);

    // ---- string-derived name (embedded identifier) ------------------------
    { FuncEvidence e; e.instrCount = 20; e.strings = {"OpenConfig"};
      auto g = GuessFromEvidence(e); CHECK_EQ(g.name, "OpenConfig"); CHECK(g.guessed); }
    { FuncEvidence e; e.instrCount = 20; e.strings = {"%s: error %d\n", "ok"};  // not identifier-like
      CHECK(!GuessFromEvidence(e).guessed); }

    // ---- nothing to go on -> no guess -------------------------------------
    { FuncEvidence e; e.instrCount = 40; e.callCount = 0;
      CHECK(!GuessFromEvidence(e).guessed); }

    if (g_fail == 0) std::printf("function_namer_test: ALL PASS\n");
    else             std::printf("function_namer_test: %d FAIL\n", g_fail);
    return g_fail ? 1 : 0;
}
