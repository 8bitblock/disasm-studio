#pragma once
//
// DllDebugPlan.h
// Pure planning for launching a PE DLL under a bitness-compatible host.  This
// module deliberately does not start processes or query Windows directories:
// callers inject system-host path resolution, which keeps validation and
// command-line construction unit-testable off Windows.
//

#include "BinaryFile.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace ds {

enum class DllBitness { Unknown, X86, X64 };

struct DllCallableExport {
    std::string name;                 // empty for an ordinal-only export
    uint64_t    ordinal = 0;
    uint32_t    rva = 0;
    uint64_t    preferredVA = 0;
};

struct DllInspection {
    bool valid = false;
    bool isDll = false;
    DllBitness bitness = DllBitness::Unknown;
    MachineArch machine = MachineArch::Unknown;
    uint64_t preferredImageBase = 0;
    std::optional<uint32_t> dllMainRva;
    std::vector<DllCallableExport> callableExports;
    std::vector<std::string> evidence;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

// Validate the already bounded BinaryFile PE model and retain only exports
// which map to executable, file-backed code in this DLL. Forwarders and data
// exports remain visible through BinaryFile::exports(), but are not callable
// launch choices.
DllInspection InspectDllForDebug(const BinaryFile& binary);

enum class DllExportSelectorKind { None, Name, Ordinal };

struct DllExportSelector {
    DllExportSelectorKind kind = DllExportSelectorKind::None;
    std::string name;
    uint64_t ordinal = 0;

    static DllExportSelector ByName(std::string value);
    static DllExportSelector ByOrdinal(uint64_t value);
};

enum class DllHostMode { SystemRundll32, CustomExecutable };

// These are policies, not literal paths. The integration layer resolves the
// requested policy using GetSystemDirectoryW/GetWindowsDirectoryW (or an
// equivalent trusted source) and returns the full rundll32.exe path.
enum class DllSystemHostPath {
    NativeSystem32,
    Wow64SysWOW64,
};

using DllSystemHostResolver =
    std::function<std::optional<std::string>(DllSystemHostPath)>;

struct DllHostEnvironment {
    // Native Windows/OS architecture, not merely the current app process.
    // X64 means that both native System32 and WOW64 SysWOW64 are available.
    DllBitness nativeWindowsBitness = DllBitness::Unknown;
    DllSystemHostResolver resolveSystemRundll32;
};

enum class DllCustomArgumentKind {
    Literal,
    DllPath,
    ExportInvocation,               // export name or #ordinal
    UserArguments,                  // expands to zero or more argv entries
};

struct DllCustomArgument {
    DllCustomArgumentKind kind = DllCustomArgumentKind::Literal;
    std::string literal;

    static DllCustomArgument Literal(std::string value);
    static DllCustomArgument DllPath();
    static DllCustomArgument Export();
    static DllCustomArgument UserArguments();
};

struct DllCustomHostPlan {
    std::string executable;
    // A typed argv plan prevents placeholder substitution or string
    // concatenation from accidentally changing Windows argument boundaries.
    std::vector<DllCustomArgument> arguments;
    // When known, enforce a bitness match. Unknown is accepted with a warning
    // because custom hosts may be scripts or launchers whose image is external.
    DllBitness bitness = DllBitness::Unknown;
};

struct DllDebugLaunchRequest {
    std::string dllPath;             // full path intended for the launched host
    DllHostMode hostMode = DllHostMode::SystemRundll32;
    DllExportSelector exportToInvoke;
    std::vector<std::string> userArguments;
    DllCustomHostPlan customHost;
    bool breakOnDllMain = true;
    bool breakOnExport = true;
};

enum class DllBreakpointKind { DllMain, Export };

struct DllBreakpointTarget {
    DllBreakpointKind kind = DllBreakpointKind::DllMain;
    std::string label;
    uint32_t rva = 0;
    uint64_t preferredVA = 0;
    uint64_t runtimeVA = 0;          // filled after the module-load event
};

struct DllRetargetMetadata {
    std::string requestedDllPath;
    std::string loadedDllPath;
    uint64_t preferredImageBase = 0;
    uint64_t loadedImageBase = 0;
    bool matched = false;
    std::vector<std::string> evidence;
    std::vector<std::string> errors;
};

struct DllDebugLaunchPlan {
    bool valid = false;
    DllInspection inspection;
    DllHostMode hostMode = DllHostMode::SystemRundll32;
    std::optional<DllSystemHostPath> systemHostPolicy;
    std::string executable;
    // argv always includes executable at index zero. Pass executable separately
    // as CreateProcessW::lpApplicationName, and a mutable wide conversion of
    // commandLine as lpCommandLine.
    std::vector<std::string> argv;
    std::string commandLine;
    std::optional<DllCallableExport> selectedExport;
    std::string exportInvocation;    // exact name or #ordinal spelling
    uint32_t targetExportRva = 0;
    std::vector<DllBreakpointTarget> breakpoints;
    DllRetargetMetadata retarget;
    std::vector<std::string> evidence;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
};

DllDebugLaunchPlan BuildDllDebugLaunchPlan(
    const BinaryFile& binary,
    const DllDebugLaunchRequest& request,
    const DllHostEnvironment& environment);

// Update breakpoint runtime VAs after LOAD_DLL_DEBUG_EVENT identifies the
// requested module. Matching is case-insensitive; a leaf-name match is accepted
// only when the debug event could report no directory at all. Two different
// absolute paths are never treated as the same DLL.
bool RetargetDllDebugLaunchPlan(DllDebugLaunchPlan& plan,
                                const std::string& loadedDllPath,
                                uint64_t loadedImageBase);

// Microsoft/CRT-compatible argv quoting. These functions preserve empty
// arguments, embedded quotes, and runs of backslashes before quotes/end quote.
std::string QuoteWindowsCommandLineArgument(const std::string& argument);
std::string BuildWindowsCommandLine(const std::vector<std::string>& argv);

} // namespace ds
