#include "DllDebugPlan.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>
#include <utility>

namespace ds {
namespace {

constexpr uint16_t kImageFileDll = 0x2000u;

bool HasNul(const std::string& value) {
    return value.find('\0') != std::string::npos;
}

bool AddPreferredVA(uint64_t base, uint32_t rva, uint64_t& out) {
    if (rva > std::numeric_limits<uint64_t>::max() - base) return false;
    out = base + rva;
    return true;
}

bool IsAbsoluteWindowsPath(const std::string& path) {
    if (path.size() >= 3 && std::isalpha(static_cast<unsigned char>(path[0])) &&
        path[1] == ':' && (path[2] == '\\' || path[2] == '/')) return true;
    return path.size() >= 2 &&
           (path[0] == '\\' || path[0] == '/') &&
           (path[1] == '\\' || path[1] == '/');
}

std::string BitnessName(DllBitness bitness) {
    switch (bitness) {
        case DllBitness::X86: return "x86";
        case DllBitness::X64: return "x64";
        default: return "unknown";
    }
}

bool IsExecutableBackedRva(const BinaryFile& binary, uint32_t rva) {
    for (const auto& section : binary.sections()) {
        if (rva < section.virtualAddress) continue;
        const uint64_t delta = static_cast<uint64_t>(rva) - section.virtualAddress;
        if (delta >= section.virtualSize) continue;
        if (!section.executable || delta >= section.rawSize) return false;
        size_t available = 0;
        return binary.ptrFromRVA(rva, available) != nullptr && available != 0;
    }
    return false;
}

std::string NormalizeWindowsPath(std::string value) {
    for (char& ch : value) {
        if (ch == '/') ch = '\\';
        else ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    if (value.rfind("\\\\?\\unc\\", 0) == 0)
        value = "\\\\" + value.substr(8);
    else if (value.rfind("\\\\?\\", 0) == 0 || value.rfind("\\??\\", 0) == 0)
        value.erase(0, 4);
    while (value.size() > 3 && value.back() == '\\') value.pop_back();
    return value;
}

std::string WindowsPathLeaf(const std::string& normalized) {
    const size_t pos = normalized.find_last_of('\\');
    return pos == std::string::npos ? normalized : normalized.substr(pos + 1);
}

void AppendError(DllDebugLaunchPlan& plan, std::string error) {
    plan.errors.push_back(std::move(error));
}

const BinaryFile::Export* FindRawExport(const BinaryFile& binary,
                                        const DllExportSelector& selector) {
    for (const auto& value : binary.exports()) {
        if (selector.kind == DllExportSelectorKind::Name && value.name == selector.name)
            return &value;
        if (selector.kind == DllExportSelectorKind::Ordinal && value.ordinal == selector.ordinal)
            return &value;
    }
    return nullptr;
}

std::optional<DllCallableExport> FindCallableExport(
    const DllInspection& inspection,
    const DllExportSelector& selector) {
    for (const auto& value : inspection.callableExports) {
        if (selector.kind == DllExportSelectorKind::Name && value.name == selector.name)
            return value;
        if (selector.kind == DllExportSelectorKind::Ordinal && value.ordinal == selector.ordinal)
            return value;
    }
    return std::nullopt;
}

} // namespace

DllExportSelector DllExportSelector::ByName(std::string value) {
    DllExportSelector result;
    result.kind = DllExportSelectorKind::Name;
    result.name = std::move(value);
    return result;
}

DllExportSelector DllExportSelector::ByOrdinal(uint64_t value) {
    DllExportSelector result;
    result.kind = DllExportSelectorKind::Ordinal;
    result.ordinal = value;
    return result;
}

DllCustomArgument DllCustomArgument::Literal(std::string value) {
    DllCustomArgument result;
    result.kind = DllCustomArgumentKind::Literal;
    result.literal = std::move(value);
    return result;
}

DllCustomArgument DllCustomArgument::DllPath() {
    DllCustomArgument result;
    result.kind = DllCustomArgumentKind::DllPath;
    return result;
}

DllCustomArgument DllCustomArgument::Export() {
    DllCustomArgument result;
    result.kind = DllCustomArgumentKind::ExportInvocation;
    return result;
}

DllCustomArgument DllCustomArgument::UserArguments() {
    DllCustomArgument result;
    result.kind = DllCustomArgumentKind::UserArguments;
    return result;
}

DllInspection InspectDllForDebug(const BinaryFile& binary) {
    DllInspection result;
    result.machine = binary.machine();
    result.preferredImageBase = binary.imageBase();

    if (!binary.loaded()) {
        result.errors.emplace_back("No binary is loaded.");
        return result;
    }
    if (binary.format() != BinFormat::PE32 && binary.format() != BinFormat::PE32Plus) {
        result.errors.emplace_back("Debug a DLL requires a PE32 or PE32+ image.");
        return result;
    }

    result.isDll = binary.isDll();
    if (!result.isDll) {
        result.errors.emplace_back("The PE COFF Characteristics field does not contain IMAGE_FILE_DLL.");
    } else {
        result.evidence.emplace_back("PE COFF Characteristics contains IMAGE_FILE_DLL (0x2000).");
    }
    if ((binary.fileCharacteristics() & kImageFileDll) == 0 && binary.isDll()) {
        // Defensive consistency check should the BinaryFile accessor ever change.
        result.errors.emplace_back("The parsed DLL characteristic is internally inconsistent.");
    }

    if (binary.format() == BinFormat::PE32 && !binary.is64Bit() &&
        binary.machine() == MachineArch::X86) {
        result.bitness = DllBitness::X86;
    } else if (binary.format() == BinFormat::PE32Plus && binary.is64Bit() &&
               binary.machine() == MachineArch::X64) {
        result.bitness = DllBitness::X64;
    } else {
        result.errors.emplace_back(
            "Only internally consistent x86 PE32 and x64 PE32+ DLLs are supported by this host workflow.");
    }
    if (result.bitness != DllBitness::Unknown) {
        result.evidence.emplace_back("Validated PE optional-header width and COFF machine as " +
                                     BitnessName(result.bitness) + ".");
    }

    const uint64_t entry = binary.entryPoint();
    if (entry != 0) {
        if (entry > std::numeric_limits<uint32_t>::max()) {
            result.warnings.emplace_back("The DLL entry-point RVA is outside the PE32 RVA range.");
        } else if (!IsExecutableBackedRva(binary, static_cast<uint32_t>(entry))) {
            result.warnings.emplace_back(
                "The DLL entry point is not backed by an executable section; no DllMain breakpoint was planned.");
        } else {
            result.dllMainRva = static_cast<uint32_t>(entry);
            result.evidence.emplace_back("Validated a file-backed executable DLL entry point.");
        }
    } else {
        result.evidence.emplace_back("The DLL declares no entry point (AddressOfEntryPoint is zero).");
    }

    constexpr size_t kMaxCallableExports = 200000;
    result.callableExports.reserve(std::min(binary.exports().size(), kMaxCallableExports));
    for (const auto& value : binary.exports()) {
        if (result.callableExports.size() >= kMaxCallableExports) {
            result.warnings.emplace_back("Callable export enumeration reached its safety cap.");
            break;
        }
        if (value.forwarded || !value.mapped || !value.isCode || value.rva == 0 ||
            value.rva > std::numeric_limits<uint32_t>::max()) continue;
        const uint32_t rva = static_cast<uint32_t>(value.rva);
        if (!IsExecutableBackedRva(binary, rva)) continue;
        uint64_t preferredVA = 0;
        if (!AddPreferredVA(binary.imageBase(), rva, preferredVA)) continue;
        result.callableExports.push_back(
            {value.name, value.ordinal, rva, preferredVA});
    }
    result.evidence.emplace_back("Found " + std::to_string(result.callableExports.size()) +
                                 " non-forwarded, file-backed code export(s).");

    result.valid = result.errors.empty();
    return result;
}

std::string QuoteWindowsCommandLineArgument(const std::string& argument) {
    const bool mustQuote = argument.empty() ||
        argument.find_first_of(" \t\n\v\f\r\"") != std::string::npos;
    if (!mustQuote) return argument;

    std::string result;
    result.reserve(argument.size() + 2);
    result.push_back('"');
    size_t backslashes = 0;
    for (char ch : argument) {
        if (ch == '\\') {
            ++backslashes;
            continue;
        }
        if (ch == '"') {
            result.append(backslashes * 2 + 1, '\\');
            result.push_back('"');
        } else {
            result.append(backslashes, '\\');
            result.push_back(ch);
        }
        backslashes = 0;
    }
    // Backslashes immediately before the closing quote must be doubled.
    result.append(backslashes * 2, '\\');
    result.push_back('"');
    return result;
}

std::string BuildWindowsCommandLine(const std::vector<std::string>& argv) {
    std::string result;
    for (size_t i = 0; i < argv.size(); ++i) {
        if (i) result.push_back(' ');
        result += QuoteWindowsCommandLineArgument(argv[i]);
    }
    return result;
}

DllDebugLaunchPlan BuildDllDebugLaunchPlan(
    const BinaryFile& binary,
    const DllDebugLaunchRequest& request,
    const DllHostEnvironment& environment) {
    DllDebugLaunchPlan plan;
    plan.hostMode = request.hostMode;
    plan.inspection = InspectDllForDebug(binary);
    plan.evidence = plan.inspection.evidence;
    plan.warnings = plan.inspection.warnings;
    plan.errors = plan.inspection.errors;
    plan.retarget.requestedDllPath = request.dllPath;
    plan.retarget.preferredImageBase = binary.imageBase();

    if (!plan.inspection.valid) return plan;
    if (request.dllPath.empty()) AppendError(plan, "A DLL path is required.");
    else if (HasNul(request.dllPath)) AppendError(plan, "The DLL path contains an embedded NUL.");
    else if (!IsAbsoluteWindowsPath(request.dllPath))
        AppendError(plan, "The DLL path must be absolute so the loaded module can be retargeted reliably.");

    for (const auto& argument : request.userArguments) {
        if (HasNul(argument)) {
            AppendError(plan, "A user argument contains an embedded NUL.");
            break;
        }
    }

    if (request.exportToInvoke.kind == DllExportSelectorKind::Name) {
        if (request.exportToInvoke.name.empty()) {
            AppendError(plan, "The selected export name is empty.");
        } else if (HasNul(request.exportToInvoke.name)) {
            AppendError(plan, "The selected export name contains an embedded NUL.");
        } else {
            plan.selectedExport = FindCallableExport(plan.inspection, request.exportToInvoke);
            plan.exportInvocation = request.exportToInvoke.name;
        }
    } else if (request.exportToInvoke.kind == DllExportSelectorKind::Ordinal) {
        if (request.exportToInvoke.ordinal > std::numeric_limits<uint32_t>::max()) {
            AppendError(plan, "The selected export ordinal is outside the PE ordinal range.");
        } else {
            plan.selectedExport = FindCallableExport(plan.inspection, request.exportToInvoke);
            plan.exportInvocation = "#" + std::to_string(request.exportToInvoke.ordinal);
        }
    }

    if (request.exportToInvoke.kind != DllExportSelectorKind::None && !plan.selectedExport) {
        if (const auto* raw = FindRawExport(binary, request.exportToInvoke)) {
            if (raw->forwarded)
                AppendError(plan, "The selected export is a forwarder and cannot be used as a local breakpoint target.");
            else if (!raw->mapped || !raw->isCode)
                AppendError(plan, "The selected export does not map to executable code in this DLL.");
            else
                AppendError(plan, "The selected export failed bounded executable-range validation.");
        } else {
            AppendError(plan, "The selected export was not found in the DLL export table.");
        }
    }

    if (plan.selectedExport) {
        plan.targetExportRva = plan.selectedExport->rva;
        plan.evidence.emplace_back("Selected export " + plan.exportInvocation + " at RVA 0x" + [&] {
            std::ostringstream text;
            text << std::hex << plan.targetExportRva;
            return text.str();
        }() + ".");
    }

    if (request.hostMode == DllHostMode::SystemRundll32) {
        if (!plan.selectedExport)
            AppendError(plan, "rundll32 requires a callable exported function.");
        if (request.dllPath.find(',') != std::string::npos)
            AppendError(plan, "rundll32 cannot unambiguously parse a DLL path containing a comma.");
        plan.warnings.emplace_back(
            "rundll32 can invoke only exports implementing its callback ABI; selecting executable code cannot prove the function signature.");

        if (plan.inspection.bitness == DllBitness::X64) {
            if (environment.nativeWindowsBitness != DllBitness::X64) {
                AppendError(plan, "An x64 DLL requires native x64 Windows and the native System32 host.");
            } else {
                plan.systemHostPolicy = DllSystemHostPath::NativeSystem32;
            }
        } else if (plan.inspection.bitness == DllBitness::X86) {
            if (environment.nativeWindowsBitness == DllBitness::X64)
                plan.systemHostPolicy = DllSystemHostPath::Wow64SysWOW64;
            else if (environment.nativeWindowsBitness == DllBitness::X86)
                plan.systemHostPolicy = DllSystemHostPath::NativeSystem32;
            else
                AppendError(plan, "The native Windows bitness is unknown; a safe rundll32 host cannot be selected.");
        }

        if (plan.systemHostPolicy) {
            if (!environment.resolveSystemRundll32) {
                AppendError(plan, "No trusted system rundll32 path resolver was provided.");
            } else {
                const auto resolved = environment.resolveSystemRundll32(*plan.systemHostPolicy);
                if (!resolved || resolved->empty())
                    AppendError(plan, "The requested bitness-compatible rundll32 path could not be resolved.");
                else if (HasNul(*resolved))
                    AppendError(plan, "The resolved rundll32 path contains an embedded NUL.");
                else if (!IsAbsoluteWindowsPath(*resolved))
                    AppendError(plan, "The resolved rundll32 path is not absolute.");
                else
                    plan.executable = *resolved;
            }
        }

        if (!plan.executable.empty() && plan.selectedExport) {
            plan.argv.push_back(plan.executable);
            plan.argv.push_back(request.dllPath + "," + plan.exportInvocation);
            plan.argv.insert(plan.argv.end(), request.userArguments.begin(), request.userArguments.end());
        }
    } else {
        if (request.customHost.executable.empty()) {
            AppendError(plan, "A custom host executable is required.");
        } else if (HasNul(request.customHost.executable)) {
            AppendError(plan, "The custom host executable contains an embedded NUL.");
        } else if (!IsAbsoluteWindowsPath(request.customHost.executable)) {
            AppendError(plan, "The custom host executable path must be absolute.");
        } else {
            plan.executable = request.customHost.executable;
        }

        if (request.customHost.bitness != DllBitness::Unknown &&
            request.customHost.bitness != plan.inspection.bitness) {
            AppendError(plan, "The custom host bitness does not match the target DLL.");
        } else if (request.customHost.bitness == DllBitness::Unknown) {
            plan.warnings.emplace_back("The custom host bitness is unknown; the caller must ensure it can load the DLL.");
        } else {
            plan.evidence.emplace_back("The custom host bitness matches the target DLL.");
        }

        bool sawDllPath = false;
        bool sawExport = false;
        bool sawUserArguments = false;
        if (!plan.executable.empty()) plan.argv.push_back(plan.executable);
        for (const auto& item : request.customHost.arguments) {
            switch (item.kind) {
                case DllCustomArgumentKind::Literal:
                    if (HasNul(item.literal)) AppendError(plan, "A custom-host literal argument contains an embedded NUL.");
                    else plan.argv.push_back(item.literal);
                    break;
                case DllCustomArgumentKind::DllPath:
                    sawDllPath = true;
                    plan.argv.push_back(request.dllPath);
                    break;
                case DllCustomArgumentKind::ExportInvocation:
                    sawExport = true;
                    if (!plan.selectedExport)
                        AppendError(plan, "The custom argument plan requests an export, but no callable export is selected.");
                    else
                        plan.argv.push_back(plan.exportInvocation);
                    break;
                case DllCustomArgumentKind::UserArguments:
                    sawUserArguments = true;
                    plan.argv.insert(plan.argv.end(), request.userArguments.begin(), request.userArguments.end());
                    break;
            }
        }
        if (!sawDllPath)
            plan.warnings.emplace_back("The custom argument plan does not pass the DLL path.");
        if (plan.selectedExport && !sawExport)
            plan.warnings.emplace_back("The custom argument plan does not pass the selected export spelling.");
        if (!request.userArguments.empty() && !sawUserArguments)
            plan.warnings.emplace_back("The custom argument plan does not pass the supplied user arguments.");
    }

    if (request.breakOnDllMain && plan.inspection.dllMainRva) {
        uint64_t preferredVA = 0;
        if (AddPreferredVA(binary.imageBase(), *plan.inspection.dllMainRva, preferredVA)) {
            plan.breakpoints.push_back(
                {DllBreakpointKind::DllMain, "DllMain", *plan.inspection.dllMainRva, preferredVA, 0});
        } else {
            AppendError(plan, "The preferred DllMain address overflows the address space.");
        }
    }
    if (request.breakOnExport && plan.selectedExport) {
        plan.breakpoints.push_back({DllBreakpointKind::Export,
                                    plan.exportInvocation,
                                    plan.selectedExport->rva,
                                    plan.selectedExport->preferredVA,
                                    0});
    }

    if (!plan.argv.empty()) plan.commandLine = BuildWindowsCommandLine(plan.argv);
    plan.valid = plan.errors.empty() && !plan.executable.empty() && !plan.argv.empty();
    return plan;
}

bool RetargetDllDebugLaunchPlan(DllDebugLaunchPlan& plan,
                                const std::string& loadedDllPath,
                                uint64_t loadedImageBase) {
    plan.retarget.loadedDllPath = loadedDllPath;
    plan.retarget.loadedImageBase = loadedImageBase;
    plan.retarget.matched = false;
    plan.retarget.evidence.clear();
    plan.retarget.errors.clear();
    for (auto& target : plan.breakpoints) target.runtimeVA = 0;

    if (!plan.valid) {
        plan.retarget.errors.emplace_back("The launch plan is not valid.");
        return false;
    }
    if (loadedDllPath.empty() || HasNul(loadedDllPath)) {
        plan.retarget.errors.emplace_back("The loaded module path is empty or contains an embedded NUL.");
        return false;
    }
    if (loadedImageBase == 0) {
        plan.retarget.errors.emplace_back("The loaded DLL image base is zero.");
        return false;
    }

    const std::string requested = NormalizeWindowsPath(plan.retarget.requestedDllPath);
    const std::string loaded = NormalizeWindowsPath(loadedDllPath);
    if (requested != loaded) {
        const bool loadedIsLeafOnly = loaded.find('\\') == std::string::npos;
        if (!loadedIsLeafOnly || WindowsPathLeaf(requested).empty() ||
            WindowsPathLeaf(requested) != loaded) {
            plan.retarget.errors.emplace_back("The loaded module does not match the requested DLL path or leaf name.");
            return false;
        }
        plan.retarget.evidence.emplace_back(
            "Matched the loaded module by case-insensitive DLL leaf name because the debug event reported no directory.");
    } else {
        plan.retarget.evidence.emplace_back("Matched the loaded module by case-insensitive absolute path.");
    }

    for (const auto& target : plan.breakpoints) {
        if (target.rva > std::numeric_limits<uint64_t>::max() - loadedImageBase) {
            plan.retarget.errors.emplace_back("A breakpoint RVA overflows the loaded image address space.");
            return false;
        }
    }
    for (auto& target : plan.breakpoints) target.runtimeVA = loadedImageBase + target.rva;
    plan.retarget.matched = true;
    plan.retarget.evidence.emplace_back("Retargeted DLL breakpoint RVAs to the loaded ASLR image base.");
    return true;
}

} // namespace ds
