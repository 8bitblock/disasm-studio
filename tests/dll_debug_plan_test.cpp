// Pure tests for Debug-a-DLL validation, export selection, host policy,
// command-line quoting, custom argument plans, and ASLR retargeting.
//
// Build (VS dev shell, from project root):
//   cl /std:c++20 /EHsc /I src tests\dll_debug_plan_test.cpp ^
//      src\Core\DllDebugPlan.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp

#include "Core/DllDebugPlan.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static void put16(std::vector<uint8_t>& b, size_t off, uint16_t value) {
    std::memcpy(b.data() + off, &value, sizeof(value));
}
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t value) {
    std::memcpy(b.data() + off, &value, sizeof(value));
}
static void put64(std::vector<uint8_t>& b, size_t off, uint64_t value) {
    std::memcpy(b.data() + off, &value, sizeof(value));
}
static void putstr(std::vector<uint8_t>& b, size_t off, const char* value, size_t cap) {
    std::memset(b.data() + off, 0, cap);
    std::memcpy(b.data() + off, value, std::min(std::strlen(value), cap - 1));
}
static size_t rdataOff(uint32_t rva) { return 0x400u + (rva - 0x2000u); }

static std::vector<uint8_t> buildDll(bool x64, bool dll = true) {
    std::vector<uint8_t> b(0x800, 0);
    b[0] = 'M'; b[1] = 'Z';
    constexpr uint32_t pe = 0x80;
    put32(b, 0x3C, pe);
    put32(b, pe, 0x00004550);

    const size_t coff = pe + 4;
    put16(b, coff + 0, x64 ? 0x8664 : 0x014C);
    put16(b, coff + 2, 2);
    put16(b, coff + 16, x64 ? 0xF0 : 0xE0);
    put16(b, coff + 18, static_cast<uint16_t>(0x0102u | (dll ? 0x2000u : 0u)));

    const size_t opt = coff + 20;
    put16(b, opt + 0, x64 ? 0x20B : 0x10B);
    put32(b, opt + 16, 0x1000);                  // DLL entry point
    if (x64) put64(b, opt + 24, 0x180000000ull);
    else put32(b, opt + 28, 0x400000);
    put32(b, opt + 32, 0x1000);
    put32(b, opt + 36, 0x200);
    put32(b, opt + 56, 0x3000);
    put32(b, opt + 60, 0x200);
    const size_t dirCount = x64 ? opt + 108 : opt + 92;
    const size_t exportDir = x64 ? opt + 112 : opt + 96;
    put32(b, dirCount, 16);
    put32(b, exportDir, 0x2000);
    put32(b, exportDir + 4, 0x100);              // forwarder range

    const size_t text = opt + (x64 ? 0xF0 : 0xE0);
    putstr(b, text, ".text", 8);
    put32(b, text + 8, 0x200);
    put32(b, text + 12, 0x1000);
    put32(b, text + 16, 0x200);
    put32(b, text + 20, 0x200);
    put32(b, text + 36, 0x60000020u);

    const size_t rdata = text + 40;
    putstr(b, rdata, ".rdata", 8);
    put32(b, rdata + 8, 0x400);
    put32(b, rdata + 12, 0x2000);
    put32(b, rdata + 16, 0x400);
    put32(b, rdata + 20, 0x400);
    put32(b, rdata + 36, 0x40000040u);

    const size_t ed = rdataOff(0x2000);
    put32(b, ed + 16, 5);                        // ordinal base
    put32(b, ed + 20, 4);
    put32(b, ed + 24, 3);
    put32(b, ed + 28, 0x2040);
    put32(b, ed + 32, 0x2050);
    put32(b, ed + 36, 0x2060);
    put32(b, rdataOff(0x2040) + 0, 0x1010);     // Run, code #5
    put32(b, rdataOff(0x2040) + 4, 0x1020);     // ordinal-only code #6
    put32(b, rdataOff(0x2040) + 8, 0x2080);     // forwarder #7
    put32(b, rdataOff(0x2040) + 12, 0x2180);    // data #8
    put32(b, rdataOff(0x2050) + 0, 0x2120);
    put32(b, rdataOff(0x2050) + 4, 0x2130);
    put32(b, rdataOff(0x2050) + 8, 0x2140);
    put16(b, rdataOff(0x2060) + 0, 0);
    put16(b, rdataOff(0x2060) + 2, 2);
    put16(b, rdataOff(0x2060) + 4, 3);
    putstr(b, rdataOff(0x2080), "OTHER.Real", 16);
    putstr(b, rdataOff(0x2120), "Run", 16);
    putstr(b, rdataOff(0x2130), "Forwarded", 16);
    putstr(b, rdataOff(0x2140), "DataThing", 16);
    b[0x200] = 0xC3;
    b[0x210] = 0xC3;
    b[0x220] = 0xC3;
    return b;
}

static bool loadBytes(BinaryFile& binary, const std::vector<uint8_t>& bytes,
                      const char* path) {
    {
        std::ofstream file(path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
    }
    const bool loaded = binary.load(path);
    std::remove(path);
    return loaded;
}

// Minimal inverse for the quoting grammar used by CommandLineToArgvW/the CRT.
static std::vector<std::string> parseWindowsCommandLine(const std::string& text) {
    std::vector<std::string> out;
    size_t at = 0;
    while (at < text.size()) {
        while (at < text.size() && (text[at] == ' ' || text[at] == '\t')) ++at;
        if (at == text.size()) break;
        std::string arg;
        bool quoted = false;
        while (at < text.size() && (quoted || (text[at] != ' ' && text[at] != '\t'))) {
            size_t slashes = 0;
            while (at < text.size() && text[at] == '\\') { ++slashes; ++at; }
            if (at < text.size() && text[at] == '"') {
                arg.append(slashes / 2, '\\');
                if (slashes & 1) arg.push_back('"');
                else quoted = !quoted;
                ++at;
            } else {
                arg.append(slashes, '\\');
                if (at < text.size() && (quoted || (text[at] != ' ' && text[at] != '\t')))
                    arg.push_back(text[at++]);
            }
        }
        out.push_back(std::move(arg));
    }
    return out;
}

static DllHostEnvironment hostEnvironment(DllBitness native,
                                          DllSystemHostPath* selected = nullptr) {
    DllHostEnvironment environment;
    environment.nativeWindowsBitness = native;
    environment.resolveSystemRundll32 = [selected](DllSystemHostPath policy)
        -> std::optional<std::string> {
        if (selected) *selected = policy;
        if (policy == DllSystemHostPath::NativeSystem32)
            return "C:\\Windows\\System32\\rundll32.exe";
        return "C:\\Windows\\SysWOW64\\rundll32.exe";
    };
    return environment;
}

static DllDebugLaunchRequest namedRequest(const char* path = "C:\\Lab Files\\sample.dll") {
    DllDebugLaunchRequest request;
    request.dllPath = path;
    request.exportToInvoke = DllExportSelector::ByName("Run");
    return request;
}

int main() {
    BinaryFile x86;
    BinaryFile x64;
    CHECK(loadBytes(x86, buildDll(false), "dll_plan_x86.bin"));
    CHECK(loadBytes(x64, buildDll(true), "dll_plan_x64.bin"));

    // Bounded loader metadata drives DLL, machine, entry, and callable export validation.
    {
        const auto inspect = InspectDllForDebug(x86);
        CHECK(inspect.valid && inspect.isDll);
        CHECK(inspect.bitness == DllBitness::X86);
        CHECK(inspect.machine == MachineArch::X86);
        CHECK(inspect.dllMainRva && *inspect.dllMainRva == 0x1000);
        CHECK(inspect.callableExports.size() == 2);
        CHECK(inspect.callableExports[0].name == "Run");
        CHECK(inspect.callableExports[0].ordinal == 5);
        CHECK(inspect.callableExports[0].rva == 0x1010);
        CHECK(inspect.callableExports[1].name.empty());
        CHECK(inspect.callableExports[1].ordinal == 6);
    }
    {
        const auto inspect = InspectDllForDebug(x64);
        CHECK(inspect.valid && inspect.bitness == DllBitness::X64);
        CHECK(inspect.preferredImageBase == 0x180000000ull);
        CHECK(inspect.callableExports[0].preferredVA == 0x180001010ull);
    }

    // A PE executable is not silently accepted as a DLL.
    {
        BinaryFile exe;
        CHECK(loadBytes(exe, buildDll(false, false), "dll_plan_exe.bin"));
        const auto inspect = InspectDllForDebug(exe);
        CHECK(!inspect.valid && !inspect.isDll && !inspect.errors.empty());
        const auto plan = BuildDllDebugLaunchPlan(exe, namedRequest(),
                                                  hostEnvironment(DllBitness::X64));
        CHECK(!plan.valid && plan.executable.empty());
    }

    // Host policy: x86 uses WOW64 on x64 Windows and native System32 on x86;
    // x64 always uses native System32 and cannot launch on x86 Windows.
    {
        DllSystemHostPath selected = DllSystemHostPath::NativeSystem32;
        auto request = namedRequest();
        request.userArguments = {"plain", "two words", "say \"hello\"",
                                 "C:\\path with space\\"};
        auto plan = BuildDllDebugLaunchPlan(x86, request,
                                            hostEnvironment(DllBitness::X64, &selected));
        CHECK(plan.valid);
        CHECK(selected == DllSystemHostPath::Wow64SysWOW64);
        CHECK(plan.executable == "C:\\Windows\\SysWOW64\\rundll32.exe");
        CHECK(plan.argv.size() == 6);
        CHECK(plan.argv[1] == "C:\\Lab Files\\sample.dll,Run");
        CHECK(parseWindowsCommandLine(plan.commandLine) == plan.argv);
        CHECK(plan.targetExportRva == 0x1010);
        CHECK(plan.breakpoints.size() == 2);
        CHECK(plan.breakpoints[0].kind == DllBreakpointKind::DllMain);
        CHECK(plan.breakpoints[1].kind == DllBreakpointKind::Export);
    }
    {
        DllSystemHostPath selected = DllSystemHostPath::Wow64SysWOW64;
        const auto plan = BuildDllDebugLaunchPlan(x86, namedRequest(),
                                                  hostEnvironment(DllBitness::X86, &selected));
        CHECK(plan.valid && selected == DllSystemHostPath::NativeSystem32);
    }
    {
        DllSystemHostPath selected = DllSystemHostPath::Wow64SysWOW64;
        const auto plan = BuildDllDebugLaunchPlan(x64, namedRequest(),
                                                  hostEnvironment(DllBitness::X64, &selected));
        CHECK(plan.valid && selected == DllSystemHostPath::NativeSystem32);
        CHECK(plan.executable.find("System32") != std::string::npos);
    }
    {
        const auto plan = BuildDllDebugLaunchPlan(x64, namedRequest(),
                                                  hostEnvironment(DllBitness::X86));
        CHECK(!plan.valid);
    }

    // Ordinal-only syntax is explicit and remains a separate argv boundary.
    {
        auto request = namedRequest("C:\\test\\ordinal.dll");
        request.exportToInvoke = DllExportSelector::ByOrdinal(6);
        const auto plan = BuildDllDebugLaunchPlan(x86, request,
                                                  hostEnvironment(DllBitness::X64));
        CHECK(plan.valid);
        CHECK(plan.exportInvocation == "#6");
        CHECK(plan.argv[1] == "C:\\test\\ordinal.dll,#6");
        CHECK(plan.selectedExport && plan.selectedExport->name.empty());
        CHECK(plan.targetExportRva == 0x1020);
    }

    // Forwarders and data exports stay inspectable but are rejected as local
    // invocation/breakpoint choices.
    {
        auto request = namedRequest();
        request.exportToInvoke = DllExportSelector::ByName("Forwarded");
        const auto plan = BuildDllDebugLaunchPlan(x86, request,
                                                  hostEnvironment(DllBitness::X64));
        CHECK(!plan.valid && !plan.selectedExport);
        CHECK(std::any_of(plan.errors.begin(), plan.errors.end(), [](const std::string& e) {
            return e.find("forwarder") != std::string::npos;
        }));
    }
    {
        auto request = namedRequest();
        request.exportToInvoke = DllExportSelector::ByName("DataThing");
        const auto plan = BuildDllDebugLaunchPlan(x86, request,
                                                  hostEnvironment(DllBitness::X64));
        CHECK(!plan.valid && !plan.selectedExport);
        CHECK(std::any_of(plan.errors.begin(), plan.errors.end(), [](const std::string& e) {
            return e.find("executable code") != std::string::npos;
        }));
    }

    // Custom hosts use a typed argument plan, preserve tricky argv values, and
    // enforce bitness when the host's architecture is known.
    {
        auto request = namedRequest("C:\\DLLs\\a b.dll");
        request.hostMode = DllHostMode::CustomExecutable;
        request.userArguments = {"", "x y", "slash quote\\\"tail"};
        request.customHost.executable = "C:\\Tools\\DLL Host.exe";
        request.customHost.bitness = DllBitness::X86;
        request.customHost.arguments = {
            DllCustomArgument::Literal("--load"),
            DllCustomArgument::DllPath(),
            DllCustomArgument::Literal("--call"),
            DllCustomArgument::Export(),
            DllCustomArgument::UserArguments(),
        };
        const auto plan = BuildDllDebugLaunchPlan(x86, request, {});
        CHECK(plan.valid);
        CHECK(plan.argv.size() == 8);
        CHECK(plan.argv[2] == "C:\\DLLs\\a b.dll");
        CHECK(plan.argv[4] == "Run");
        CHECK(plan.argv[5].empty());
        CHECK(parseWindowsCommandLine(plan.commandLine) == plan.argv);

        request.customHost.bitness = DllBitness::X64;
        CHECK(!BuildDllDebugLaunchPlan(x86, request, {}).valid);
    }

    // Quoting handles empty values, quotes, whitespace, and trailing slashes.
    {
        const std::vector<std::string> args = {
            "", "plain", "two words", "say \"hi\"",
            "C:\\path with space\\", "\\\\server\\quoted \"leaf\"\\"
        };
        CHECK(parseWindowsCommandLine(BuildWindowsCommandLine(args)) == args);
        CHECK(QuoteWindowsCommandLineArgument("") == "\"\"");
        CHECK(QuoteWindowsCommandLineArgument("plain") == "plain");
    }

    // LOAD_DLL_DEBUG_EVENT retargets preferred RVAs to the actual ASLR base.
    {
        auto plan = BuildDllDebugLaunchPlan(x86, namedRequest("C:\\One\\SAMPLE.dll"),
                                            hostEnvironment(DllBitness::X64));
        CHECK(plan.valid);
        CHECK(!RetargetDllDebugLaunchPlan(plan, "sample.DLL", 0x71000000));
        CHECK(!plan.retarget.matched && !plan.retarget.errors.empty());
        CHECK(RetargetDllDebugLaunchPlan(plan, "C:\\One\\sample.DLL", 0x71000000));
        CHECK(plan.retarget.matched && plan.retarget.loadedImageBase == 0x71000000);
        CHECK(plan.breakpoints[0].runtimeVA == 0x71001000);
        CHECK(plan.breakpoints[1].runtimeVA == 0x71001010);
        CHECK(RetargetDllDebugLaunchPlan(plan, "\\\\?\\C:\\One\\sample.dll", 0x71100000));
        CHECK(plan.breakpoints[1].runtimeVA == 0x71101010);
        CHECK(!RetargetDllDebugLaunchPlan(plan, "D:\\Staged\\sample.DLL", 0x72000000));
        CHECK(!plan.retarget.matched);             // same leaf, different full path is not trusted
        CHECK(!RetargetDllDebugLaunchPlan(plan, "D:\\Other\\different.dll", 0x72000000));
        CHECK(!plan.retarget.matched);
        CHECK(plan.breakpoints[0].runtimeVA == 0);
        CHECK(!RetargetDllDebugLaunchPlan(plan, "C:\\One\\sample.DLL", UINT32_MAX - 0x800));
        CHECK(!plan.retarget.matched && plan.breakpoints[0].runtimeVA == 0);
        CHECK(!RetargetDllDebugLaunchPlan(plan, "C:\\One\\sample.DLL", UINT64_MAX - 0x800));
        CHECK(!plan.retarget.matched && plan.breakpoints[1].runtimeVA == 0);
    }

    if (!g_fail) std::printf("dll_debug_plan_test: all checks passed\n");
    return g_fail ? 1 : 0;
}
