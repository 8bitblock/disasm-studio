#include "SymbolResolver.h"
#include "DbgHelpLock.h"   // serialize all DbgHelp use against the debug thread's StackWalk64
#include "Demangle.h"

#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <limits>
#include <sstream>
#include <utility>

#pragma comment(lib, "dbghelp.lib")

namespace ds {

namespace {

constexpr size_t kMaxTypeDepth = 12;
constexpr ULONG  kMaxTypeChildren = 32;
constexpr size_t kMaxTypeNodes = 1024;
constexpr size_t kMaxLocals = 256;
constexpr size_t kMaxLocalCandidates = 2048;
constexpr size_t kMaxPdbText = 4096;
constexpr size_t kMaxSearchPart = 32767;
constexpr size_t kMaxServerText = 4096;
constexpr size_t kMaxSearchPath = 32767;
// DIA's SymTagEnum values. The Windows SDK's DbgHelp header accepts these via
// TI_GET_SYMTAG but some SDK editions do not ship cvconst.h, so keep the small
// stable subset used here dependency-free.
constexpr DWORD kSymTagUDT = 11;
constexpr DWORD kSymTagEnum = 12;
constexpr DWORD kSymTagFunctionType = 13;
constexpr DWORD kSymTagPointerType = 14;
constexpr DWORD kSymTagArrayType = 15;
constexpr DWORD kSymTagBaseType = 16;
constexpr DWORD kSymTagTypedef = 17;
constexpr DWORD kSymTagFunctionArgType = 20;

bool sameOptions(const SymbolResolverOptions& a, const SymbolResolverOptions& b) {
    return a.networkEnabled == b.networkEnabled &&
           a.cacheDirectory == b.cacheDirectory &&
           a.serverUrl == b.serverUrl &&
           a.collectSourceLines == b.collectSourceLines &&
           a.collectTypes == b.collectTypes &&
           a.collectLocals == b.collectLocals;
}

std::string narrowWide(const wchar_t* value) {
    if (!value || !*value) return {};
    const size_t chars = wcsnlen_s(value, kMaxPdbText + 1);
    if (!chars) return {};
    const int inputChars = static_cast<int>((std::min)(chars, kMaxPdbText));
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, inputChars,
                                           nullptr, 0, nullptr, nullptr);
    if (count <= 0) return {};
    std::string out(static_cast<size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, inputChars,
                            out.data(), count, nullptr, nullptr) != count)
        return {};
    return out;
}

std::string boundedText(std::string value) {
    if (value.size() > kMaxPdbText) value.resize(kMaxPdbText);
    return value;
}

struct TypeQueryBudget {
    size_t remaining = kMaxTypeNodes;
};

std::string typeSymbolName(HANDLE process, DWORD64 moduleBase, ULONG typeId) {
    PWSTR value = nullptr;
    if (!SymGetTypeInfo(process, moduleBase, typeId, TI_GET_SYMNAME, &value) || !value)
        return {};
    std::string out = narrowWide(value);
    LocalFree(value);
    return out;
}

std::string basicTypeName(DWORD basic, ULONG64 length) {
    switch (basic) {
        case 1:  return "void";
        case 2:  return "char";
        case 3:  return "wchar_t";
        case 6:
            if (length == 1) return "int8_t";
            if (length == 2) return "int16_t";
            if (length == 4) return "int32_t";
            if (length == 8) return "int64_t";
            return "int";
        case 7:
            if (length == 1) return "uint8_t";
            if (length == 2) return "uint16_t";
            if (length == 4) return "uint32_t";
            if (length == 8) return "uint64_t";
            return "unsigned int";
        case 8:  return length == 4 ? "float" : length == 8 ? "double" : "long double";
        case 10: return "bool";
        case 13: return "long";
        case 14: return "unsigned long";
        case 31: return "HRESULT";
        case 32: return "char16_t";
        case 33: return "char32_t";
        default: return "unknown";
    }
}

std::vector<ULONG> typeChildren(HANDLE process, DWORD64 moduleBase, ULONG typeId) {
    DWORD requested = 0;
    if (!SymGetTypeInfo(process, moduleBase, typeId, TI_GET_CHILDRENCOUNT, &requested) || !requested)
        return {};
    const ULONG count = (std::min)(requested, kMaxTypeChildren);
    const size_t bytes = sizeof(TI_FINDCHILDREN_PARAMS) +
                         static_cast<size_t>(count - 1) * sizeof(ULONG);
    std::vector<unsigned char> storage(bytes, 0);
    auto* params = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(storage.data());
    params->Count = count;
    params->Start = 0;
    if (!SymGetTypeInfo(process, moduleBase, typeId, TI_FINDCHILDREN, params)) return {};
    return std::vector<ULONG>(params->ChildId, params->ChildId + count);
}

std::string pdbTypeName(HANDLE process, DWORD64 moduleBase, ULONG typeId,
                        TypeQueryBudget& budget, size_t depth = 0) {
    if (!typeId || depth >= kMaxTypeDepth || !budget.remaining) return "unknown";
    --budget.remaining;
    DWORD tag = 0;
    if (!SymGetTypeInfo(process, moduleBase, typeId, TI_GET_SYMTAG, &tag)) return "unknown";

    switch (tag) {
        case kSymTagBaseType: {
            DWORD basic = 0;
            ULONG64 length = 0;
            SymGetTypeInfo(process, moduleBase, typeId, TI_GET_BASETYPE, &basic);
            SymGetTypeInfo(process, moduleBase, typeId, TI_GET_LENGTH, &length);
            return basicTypeName(basic, length);
        }
        case kSymTagPointerType: {
            ULONG child = 0;
            if (!SymGetTypeInfo(process, moduleBase, typeId, TI_GET_TYPEID, &child))
                return "void*";
            return boundedText(pdbTypeName(process, moduleBase, child, budget, depth + 1) + "*");
        }
        case kSymTagArrayType: {
            ULONG child = 0;
            ULONG64 count = 0;
            SymGetTypeInfo(process, moduleBase, typeId, TI_GET_TYPEID, &child);
            SymGetTypeInfo(process, moduleBase, typeId, TI_GET_COUNT, &count);
            return boundedText(pdbTypeName(process, moduleBase, child, budget, depth + 1) + "[" +
                               std::to_string(count) + "]");
        }
        case kSymTagFunctionArgType: {
            ULONG child = 0;
            if (!SymGetTypeInfo(process, moduleBase, typeId, TI_GET_TYPEID, &child))
                return "unknown";
            return pdbTypeName(process, moduleBase, child, budget, depth + 1);
        }
        case kSymTagFunctionType: {
            ULONG returnId = 0;
            SymGetTypeInfo(process, moduleBase, typeId, TI_GET_TYPEID, &returnId);
            std::string out = pdbTypeName(process, moduleBase, returnId, budget, depth + 1) + " (";
            const auto children = typeChildren(process, moduleBase, typeId);
            for (size_t i = 0; i < children.size(); ++i) {
                if (i) out += ", ";
                out += pdbTypeName(process, moduleBase, children[i], budget, depth + 1);
                if (out.size() >= kMaxPdbText - 16) { out.resize(kMaxPdbText - 16); break; }
            }
            if (children.size() == kMaxTypeChildren) out += ", ...";
            out += ")";
            return boundedText(std::move(out));
        }
        case kSymTagTypedef:
        case kSymTagUDT:
        case kSymTagEnum: {
            std::string name = typeSymbolName(process, moduleBase, typeId);
            return name.empty() ? "unknown" : name;
        }
        default: {
            ULONG child = 0;
            if (SymGetTypeInfo(process, moduleBase, typeId, TI_GET_TYPEID, &child) &&
                child != typeId)
                return pdbTypeName(process, moduleBase, child, budget, depth + 1);
            std::string name = typeSymbolName(process, moduleBase, typeId);
            return name.empty() ? "unknown" : name;
        }
    }
}

std::string searchPathFor(const SymbolResolverOptions& options,
                          const std::string& binaryPath = {}) {
    auto safePart = [](const std::string& value, size_t maxLength) {
        return !value.empty() && value.size() <= maxLength &&
               value.find_first_of(";*\r\n") == std::string::npos &&
               value.find('\0') == std::string::npos;
    };
    auto remotePath = [](const std::string& value) {
        return value.starts_with("\\\\") || value.starts_with("//") ||
               value.find("://") != std::string::npos;
    };
    std::vector<std::string> parts;
    if (!binaryPath.empty()) {
        const std::filesystem::path parent = std::filesystem::path(binaryPath).parent_path();
        const std::string parentText = parent.string();
        if (safePart(parentText, kMaxSearchPart)) parts.push_back(parentText);
    }
    // The cache is intentionally a local store. A UNC/URL value would perform
    // network I/O even without an SRV entry and would contradict offline mode.
    const bool safeCache = safePart(options.cacheDirectory, kMaxSearchPart) &&
                           !remotePath(options.cacheDirectory);
    const bool safeServer = safePart(options.serverUrl, kMaxServerText);
    if (safeCache) parts.push_back(options.cacheDirectory);
    if (parts.empty()) parts.emplace_back(".");
    // DbgHelp treats both semicolons and `srv*...` as search-path syntax. Never
    // splice untrusted path text into that grammar: in particular, an offline
    // cache value beginning with `srv*` must not be able to enable network I/O.
    if (options.networkEnabled && safeCache && safeServer)
        parts.emplace_back("srv*" + options.cacheDirectory + "*" + options.serverUrl);

    std::string out;
    for (const auto& part : parts) {
        if (part.empty()) continue;
        const size_t separator = out.empty() ? 0 : 1;
        const size_t remaining = kMaxSearchPath - out.size();
        if (separator > remaining || part.size() > remaining - separator)
            continue;
        if (!out.empty()) out.push_back(';');
        out += part;
    }
    return out.empty() ? std::string(".") : out;
}

DWORD resolverOptions(const SymbolResolverOptions& options) {
    DWORD value = SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
                  SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS |
                  SYMOPT_CASE_INSENSITIVE;
    if (options.collectSourceLines) value |= SYMOPT_LOAD_LINES;
#ifdef SYMOPT_DISABLE_SYMSRV_AUTODETECT
    if (!options.networkEnabled) value |= SYMOPT_DISABLE_SYMSRV_AUTODETECT;
#endif
    return value;
}

class ScopedResolverOptions {
public:
    explicit ScopedResolverOptions(const SymbolResolverOptions& options)
        : previous_(SymGetOptions()) {
        SymSetOptions(resolverOptions(options));
    }
    ~ScopedResolverOptions() { SymSetOptions(previous_); }
    ScopedResolverOptions(const ScopedResolverOptions&) = delete;
    ScopedResolverOptions& operator=(const ScopedResolverOptions&) = delete;
private:
    DWORD previous_ = 0;
};

struct LocalEnumContext {
    HANDLE process = nullptr;
    SymbolRecord* record = nullptr;
    TypeQueryBudget* typeBudget = nullptr;
    size_t visited = 0;
};

BOOL CALLBACK collectLocal(PSYMBOL_INFO symbol, ULONG, PVOID opaque) {
    auto* context = static_cast<LocalEnumContext*>(opaque);
    if (!context || !context->record || !symbol) return FALSE;
    if (++context->visited > kMaxLocalCandidates) return FALSE;
    if (context->record->locals.size() >= kMaxLocals) return FALSE;
    const ULONG localFlags = SYMFLAG_LOCAL | SYMFLAG_PARAMETER;
    if (!(symbol->Flags & localFlags)) return TRUE;

    SymbolLocal value;
    value.name.assign(symbol->Name, (std::min<size_t>)(symbol->NameLen, 1024));
    value.parameter = (symbol->Flags & SYMFLAG_PARAMETER) != 0;
    if (symbol->TypeIndex && symbol->ModBase && context->typeBudget)
        value.type = pdbTypeName(context->process, symbol->ModBase,
                                 symbol->TypeIndex, *context->typeBudget);

    char location[96] = {};
    if (symbol->Flags & SYMFLAG_REGISTER) {
        std::snprintf(location, sizeof(location), "register %lu", symbol->Register);
    } else if (symbol->Flags & SYMFLAG_REGREL) {
        std::snprintf(location, sizeof(location), "register %lu %+lld", symbol->Register,
                      static_cast<long long>(static_cast<int64_t>(symbol->Address)));
    } else if (symbol->Flags & SYMFLAG_FRAMEREL) {
        std::snprintf(location, sizeof(location), "frame %+lld",
                      static_cast<long long>(static_cast<int64_t>(symbol->Address)));
    } else if (symbol->Address) {
        std::snprintf(location, sizeof(location), "0x%llX",
                      static_cast<unsigned long long>(symbol->Address));
    }
    value.location = location;
    context->record->locals.push_back(std::move(value));
    return TRUE;
}

} // namespace

std::string BuildSymbolSearchPath(const SymbolResolverOptions& options,
                                  const std::string& binaryPath) {
    return searchPathFor(options, binaryPath);
}

SymbolResolver::~SymbolResolver() { reset(); }

void SymbolResolver::configure(SymbolResolverOptions options) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (sameOptions(options_, options)) return;
    reset();
    options_ = std::move(options);
}

void SymbolResolver::reset() {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (inited_ && h_) SymCleanup((HANDLE)h_);
    inited_ = false; h_ = nullptr; live_ = false;
    loaded_.clear(); binaryPath_.clear(); binaryImageBase_ = 0;
}

bool SymbolResolver::useLive(void* hProcess) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (inited_ && live_ && h_ == hProcess) return true;   // already bound to this process
    reset();
    if (!hProcess) return false;
    const std::string search = BuildSymbolSearchPath(options_);
    ScopedResolverOptions scopedOptions(options_);
    if (SymInitialize((HANDLE)hProcess, search.c_str(), FALSE)) {
        SymSetSearchPath((HANDLE)hProcess, search.c_str());
        inited_ = true; live_ = true; h_ = hProcess;
        return true;
    }
    return false;
}

bool SymbolResolver::useBinary(const std::string& path, uint64_t imageBase) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (inited_ && !live_ && binaryPath_ == path && binaryImageBase_ == imageBase) return true;
    reset();
    if (path.empty()) return false;
    const std::string search = BuildSymbolSearchPath(options_, path);
    ScopedResolverOptions scopedOptions(options_);
    // DbgHelp only requires a unique, non-zero session key when fInvadeProcess
    // is false. `this` is lifetime-stable and prevents multiple static
    // documents from colliding on the old process-wide constant key.
    HANDLE fake = reinterpret_cast<HANDLE>(this);
    if (SymInitialize(fake, search.c_str(), FALSE)) {
        SymSetSearchPath(fake, search.c_str());
        inited_ = true; live_ = false; h_ = (void*)fake;
        binaryPath_ = path; binaryImageBase_ = imageBase;
        // size 0 asks DbgHelp to read the on-disk image headers. A successful
        // SymInitialize without a loaded image is not a usable symbol session.
        if (SymLoadModuleEx(fake, nullptr, path.c_str(), nullptr,
                            imageBase, 0, nullptr, 0))
            return true;
        reset();
    }
    return false;
}

void SymbolResolver::ensureModule(uint64_t base, uint64_t size, const std::string& imagePath) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    if (!inited_ || !live_ || !base) return;
    ScopedResolverOptions scopedOptions(options_);
    if (std::find(loaded_.begin(), loaded_.end(), base) != loaded_.end()) return;
    const DWORD moduleSize = size > (std::numeric_limits<DWORD>::max)()
                           ? (std::numeric_limits<DWORD>::max)()
                           : static_cast<DWORD>(size);
    if (SymLoadModuleEx((HANDLE)h_, nullptr,
                        imagePath.empty() ? nullptr : imagePath.c_str(), nullptr,
                        base, moduleSize, nullptr, 0))
        loaded_.push_back(base);
}

bool SymbolResolver::resolve(uint64_t addr, std::string& nameOut, uint64_t& dispOut) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    nameOut.clear();
    dispOut = 0;
    if (!inited_ || !h_) return false;
    ScopedResolverOptions scopedOptions(options_);
    // SYMBOL_INFO + room for the name; ULONG64 array guarantees 8-byte alignment.
    ULONG64 buffer[(sizeof(SYMBOL_INFO) + 512 + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
    SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(buffer);
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen   = 511;
    DWORD64 disp = 0;
    if (SymFromAddr((HANDLE)h_, addr, &disp, si) && si->NameLen) {
        nameOut = boundedText(DemangleForLabel(std::string_view(si->Name, si->NameLen)));
        dispOut = (uint64_t)disp;
        return true;
    }
    return false;
}

bool SymbolResolver::resolveDetailed(uint64_t addr, SymbolRecord& recordOut) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    recordOut = {};
    recordOut.queryAddress = addr;
    if (!inited_ || !h_) return false;
    ScopedResolverOptions scopedOptions(options_);

    ULONG64 buffer[(sizeof(SYMBOL_INFO) + 1024 + sizeof(ULONG64) - 1) / sizeof(ULONG64)]{};
    SYMBOL_INFO* symbol = reinterpret_cast<SYMBOL_INFO*>(buffer);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = 1023;
    DWORD64 displacement = 0;
    const HANDLE process = (HANDLE)h_;
    if (!SymFromAddr(process, addr, &displacement, symbol) || !symbol->NameLen) return false;

    recordOut.found = true;
    recordOut.symbolAddress = symbol->Address;
    recordOut.displacement = displacement;
    recordOut.name = boundedText(
        DemangleForLabel(std::string_view(symbol->Name, symbol->NameLen)));

    TypeQueryBudget typeBudget;

    if (options_.collectSourceLines) {
        IMAGEHLP_LINE64 line{};
        line.SizeOfStruct = sizeof(line);
        DWORD lineDisplacement = 0;
        if (SymGetLineFromAddr64(process, addr, &lineDisplacement, &line) && line.FileName) {
            recordOut.source.file.assign(line.FileName,
                strnlen_s(line.FileName, kMaxPdbText));
            recordOut.source.line = line.LineNumber;
            recordOut.source.displacement = lineDisplacement;
        }
    }

    if (options_.collectTypes && symbol->TypeIndex && symbol->ModBase)
        recordOut.prototype = boundedText(
            pdbTypeName(process, symbol->ModBase, symbol->TypeIndex, typeBudget));

    if (options_.collectLocals) {
        IMAGEHLP_STACK_FRAME frame{};
        frame.InstructionOffset = addr;
        if (SymSetContext(process, &frame, nullptr)) {
            LocalEnumContext context{process, &recordOut, &typeBudget};
            SymEnumSymbols(process, 0, nullptr, collectLocal, &context);
        }
    }
    return true;
}

bool SymbolResolver::addressOf(const std::string& name, uint64_t& addrOut) {
    std::lock_guard<std::recursive_mutex> lk(DbgHelpMutex());
    addrOut = 0;
    if (!inited_ || !h_ || name.empty() || name.size() > kMaxPdbText) return false;
    ScopedResolverOptions scopedOptions(options_);
    ULONG64 buffer[(sizeof(SYMBOL_INFO) + 512 + sizeof(ULONG64) - 1) / sizeof(ULONG64)];
    SYMBOL_INFO* si = reinterpret_cast<SYMBOL_INFO*>(buffer);
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen   = 511;
    if (SymFromName((HANDLE)h_, name.c_str(), si)) {
        addrOut = (uint64_t)si->Address;
        return true;
    }
    return false;
}

} // namespace ds
