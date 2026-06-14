#pragma once
//
// ApiInfo.h
// One-line behavioral descriptions for common imported APIs, shared by the
// listing's inline comments (BinaryViewTab) and the per-function annotation
// engine (FuncAnnotate). Matched case-insensitively on the function name with
// any "dll." prefix stripped; A/W/Ex suffixes and Nt/Zw prefixes fall out of
// the substring matching. Header-only and pure so it unit-tests in isolation.
//
#include <cctype>
#include <string>

namespace ds {

// One-line purpose for a (possibly "dll.func"-qualified) API name. "" when unknown.
inline std::string ApiPurpose(const std::string& dllDotFunc) {
    std::string fn = dllDotFunc;
    size_t dot = fn.find('.');
    if (dot != std::string::npos) fn = fn.substr(dot + 1);
    for (char& c : fn) c = (char)std::tolower((unsigned char)c);
    auto has = [&](const char* k) { return fn.find(k) != std::string::npos; };
    if (has("createfile"))        return "open / create a file or device";
    if (has("readfile"))          return "read from a file/handle";
    if (has("writefile"))         return "write to a file/handle";
    if (has("createprocess") || has("winexec") || has("shellexecute")) return "spawn a process";
    if (has("virtualalloc"))      return "allocate memory (often RWX)";
    if (has("virtualprotect"))    return "change memory protection";
    if (has("writeprocessmemory"))return "write another process's memory";
    if (has("readprocessmemory")) return "read another process's memory";
    if (has("createremotethread") || has("ntcreatethreadex")) return "start a thread in another process";
    if (has("queueuserapc"))      return "queue an APC (injection)";
    if (has("loadlibrary"))       return "load a DLL at runtime";
    if (has("getprocaddress"))    return "resolve an export by name";
    if (has("getmodulehandle"))   return "get a loaded module base";
    if (has("isdebuggerpresent") || has("checkremotedebugger")) return "anti-debug check";
    if (has("ntqueryinformationprocess")) return "query process info (often anti-debug)";
    if (has("setwindowshookex"))  return "install a hook (injection)";
    if (has("regsetvalue") || has("regcreatekey")) return "write the registry (persistence?)";
    if (has("regopenkey") || has("regqueryvalue")) return "read the registry";
    if (has("createservice"))     return "install a service (persistence)";
    if (has("wsastartup") || has("socket") || has("connect") || has("send") || has("recv")) return "network socket I/O";
    if (has("internetopen") || has("internetconnect") || has("httpsendrequest") || has("winhttp") || has("urldownload")) return "HTTP / internet I/O";
    if (has("crypt") || has("bcrypt"))   return "cryptography";
    if (has("messagebox"))        return "show a message box";
    if (has("exitprocess") || has("terminateprocess")) return "terminate the process";
    if (has("getprocessheap") || has("heapalloc")) return "heap allocation";
    if (has("sleep"))             return "delay execution";
    if (has("gettickcount") || has("queryperformancecounter") || has("timegettime")) return "read a timer (timing/anti-debug)";
    if (has("createmutex"))       return "create a mutex (single-instance?)";
    // String / input / UI APIs the annotation engine reasons about.
    if (has("strcmp") || has("stricmp") || has("memcmp") || has("wcscmp") || has("comparestring")) return "compare strings/memory";
    if (has("strcpy") || has("strncpy") || has("wcscpy") || has("lstrcpy")) return "copy a string";
    if (has("strlen") || has("wcslen") || has("lstrlen")) return "string length";
    if (has("readconsole") || has("getchar") || has("_getch") || has("scanf") || (has("gets") && !has("getsystem"))) return "read user input";
    if (has("getwindowtext") || has("getdlgitemtext")) return "read text from a UI control";
    if (has("getasynckeystate") || has("getkeystate") || has("getkeyboardstate")) return "poll keyboard state (input handler?)";
    if (has("getcursorpos") || has("setcursorpos")) return "mouse cursor position (input?)";
    if (has("peekmessage") || has("getmessage") || has("dispatchmessage")) return "Windows message pump";
    if (has("settimer"))          return "register a periodic timer callback";
    if (has("createthread"))      return "start a thread";
    if (has("registerclass"))     return "register a window class (WndProc callback)";
    if (has("getenvironmentvariable")) return "read an environment variable";
    if (has("getcommandline"))    return "read the command line";
    if (has("findfirstfile") || has("findnextfile")) return "enumerate files";
    if (has("getmodulefilename")) return "get a module's path";
    if (has("rand") && fn.size() <= 6) return "pseudo-random number";   // rand / srand
    return std::string();
}

} // namespace ds
