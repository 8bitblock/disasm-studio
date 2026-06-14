#pragma once
//
// ExcName.h
// Semantic names for the Win32 exception codes a debugger actually meets, so
// the UI can show "ACCESS_VIOLATION (0xC0000005)" instead of a bare number.
// Header-only and Windows-header-free (codes are plain constants), so it is
// cl-testable off target and usable from any UI or core file.
//
#include <cstdint>
#include <cstdio>
#include <string>

namespace ds {

// The common exception/status codes, by value. Returns nullptr when unknown
// (callers fall back to hex via ExceptionCodeLabel).
inline const char* ExceptionCodeName(uint32_t code) {
    switch (code) {
        case 0xC0000005u: return "ACCESS_VIOLATION";
        case 0x80000003u: return "BREAKPOINT";
        case 0x80000004u: return "SINGLE_STEP";
        case 0x4000001Fu: return "WX86_BREAKPOINT";        // 32-bit int3 under WOW64
        case 0x4000001Eu: return "WX86_SINGLE_STEP";       // 32-bit #DB under WOW64
        case 0x80000002u: return "DATATYPE_MISALIGNMENT";
        case 0xC0000094u: return "INT_DIVIDE_BY_ZERO";
        case 0xC0000095u: return "INT_OVERFLOW";
        case 0xC000008Eu: return "FLT_DIVIDE_BY_ZERO";
        case 0xC0000090u: return "FLT_INVALID_OPERATION";
        case 0xC000001Du: return "ILLEGAL_INSTRUCTION";
        case 0xC0000096u: return "PRIV_INSTRUCTION";
        case 0xC00000FDu: return "STACK_OVERFLOW";
        case 0xC0000374u: return "HEAP_CORRUPTION";
        case 0xC0000409u: return "STACK_BUFFER_OVERRUN";   // /GS or fail-fast
        case 0xC0000008u: return "INVALID_HANDLE";
        case 0xC0000135u: return "DLL_NOT_FOUND";
        case 0xC0000142u: return "DLL_INIT_FAILED";
        case 0xC06D007Eu: return "DELAYLOAD_MOD_NOT_FOUND";
        case 0xE06D7363u: return "CPP_EXCEPTION";          // MSVC C++ throw
        case 0xE0434352u: return "CLR_EXCEPTION";          // .NET managed throw
        case 0x406D1388u: return "SET_THREAD_NAME";        // MSVC thread-naming convention
        case 0x40010006u: return "DBG_PRINTEXCEPTION";     // OutputDebugStringA path
        case 0x4001000Au: return "DBG_PRINTEXCEPTION_W";   // OutputDebugStringW path
        default:          return nullptr;
    }
}

// "ACCESS_VIOLATION (0xC0000005)" for known codes, "exception 0x..." otherwise.
inline std::string ExceptionCodeLabel(uint32_t code) {
    char buf[64];
    if (const char* n = ExceptionCodeName(code)) {
        std::snprintf(buf, sizeof(buf), "%s (0x%08X)", n, code);
    } else {
        std::snprintf(buf, sizeof(buf), "exception 0x%08X", code);
    }
    return buf;
}

} // namespace ds
