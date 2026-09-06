#include "ValidationApiCatalog.h"

#include <algorithm>
#include <utility>

namespace ds {
namespace {

using Encoding = ValidationDataEncoding;
using InputBinding = ValidationInputBinding;
using EqualityRule = ValidationEqualityRule;

struct CatalogRow {
    ValidationApiKind kind = ValidationApiKind::InputProducer;
    std::string_view dll;
    std::string_view key;
    std::string_view canonical;
    ValidationInputProducerContract input;
    ValidationEqualityComparatorContract comparator;
};

struct ProducerSpec {
    std::string_view key;
    std::string_view canonical;
    ValidationInputProducerContract contract;
};

struct ComparatorSpec {
    std::string_view key;
    std::string_view canonical;
    ValidationEqualityComparatorContract contract;
};

struct DirectProducerSpec {
    std::string_view dll;
    ProducerSpec producer;
};

struct DirectComparatorSpec {
    std::string_view dll;
    ComparatorSpec comparator;
};

template <typename T, size_t N>
constexpr size_t ArrayCount(const T (&)[N]) noexcept {
    return N;
}

constexpr ValidationInputProducerContract FixedOutput(
    uint8_t outputArgumentIndex,
    Encoding encoding,
    bool returnValueAliasesOutput,
    std::string_view meaning) {
    ValidationInputProducerContract result;
    result.binding = InputBinding::FixedOutputArgument;
    result.outputArgumentIndex = outputArgumentIndex;
    result.outputArgumentIndexValid = true;
    result.encoding = encoding;
    result.returnValueAliasesOutput = returnValueAliasesOutput;
    result.meaning = meaning;
    return result;
}

constexpr ValidationInputProducerContract FormatDriven(
    uint8_t formatArgumentIndex,
    uint8_t firstOutputArgumentIndex,
    std::string_view meaning) {
    ValidationInputProducerContract result;
    result.binding = InputBinding::FormatDrivenArguments;
    result.formatArgumentIndex = formatArgumentIndex;
    result.formatArgumentIndexValid = true;
    result.firstOutputArgumentIndex = firstOutputArgumentIndex;
    result.firstOutputArgumentIndexValid = true;
    result.encoding = Encoding::FormatDependent;
    result.meaning = meaning;
    return result;
}

constexpr ValidationEqualityComparatorContract Comparator(
    uint8_t leftArgumentIndex,
    uint8_t rightArgumentIndex,
    Encoding encoding,
    EqualityRule rule,
    int32_t equalityValue,
    std::string_view meaning,
    bool firstLengthValid = false,
    uint8_t firstLengthArgumentIndex = 0,
    bool secondLengthValid = false,
    uint8_t secondLengthArgumentIndex = 0) {
    ValidationEqualityComparatorContract result;
    result.leftArgumentIndex = leftArgumentIndex;
    result.rightArgumentIndex = rightArgumentIndex;
    result.encoding = encoding;
    result.equalityRule = rule;
    result.equalityValue = equalityValue;
    result.meaning = meaning;
    if (firstLengthValid)
        result.lengthArgumentIndices[result.lengthArgumentCount++] =
            firstLengthArgumentIndex;
    if (secondLengthValid)
        result.lengthArgumentIndices[result.lengthArgumentCount++] =
            secondLengthArgumentIndex;
    return result;
}

constexpr std::string_view kFixedStdioModules[] = {
    "msvcrt", "ucrtbase",
    "msvcr70", "msvcr71", "msvcr80", "msvcr90", "msvcr100",
    "msvcr110", "msvcr120",
    "api-ms-win-crt-stdio-l1-1-0",
};

// The UCRT's scanf-family front ends are inline wrappers around the exported
// __stdio_common_* entry points, so a PE cannot import scanf/wscanf directly
// from ucrtbase.dll or its stdio API-set contract. Legacy CRT DLLs do export
// these names.
constexpr std::string_view kFormattedStdioModules[] = {
    "msvcrt",
    "msvcr70", "msvcr71", "msvcr80", "msvcr90", "msvcr100",
    "msvcr110", "msvcr120",
};

// Annex-K/secure CRT entry points were introduced after the earliest versioned
// CRTs and are not exported by the system msvcrt compatibility runtime. Keep
// this list separate so exact lookup never manufactures those DLL/API pairs.
constexpr std::string_view kSecureFixedStdioModules[] = {
    "ucrtbase", "msvcr80", "msvcr90", "msvcr100", "msvcr110",
    "msvcr120", "api-ms-win-crt-stdio-l1-1-0",
};


constexpr std::string_view kSecureFormattedStdioModules[] = {
    "msvcr80", "msvcr90", "msvcr100", "msvcr110", "msvcr120",
};

constexpr std::string_view kStringModules[] = {
    "msvcrt", "ucrtbase",
    "msvcr70", "msvcr71", "msvcr80", "msvcr90", "msvcr100",
    "msvcr110", "msvcr120",
    "api-ms-win-crt-string-l1-1-0",
};

constexpr std::string_view kConioModules[] = {
    "msvcrt", "ucrtbase", "msvcr80", "msvcr90", "msvcr100",
    "msvcr110", "msvcr120", "api-ms-win-crt-conio-l1-1-0",
};

constexpr DirectProducerSpec kDirectProducers[] = {
    {"kernel32", {"readconsolea", "ReadConsoleA",
        FixedOutput(1, Encoding::NarrowText, false,
                    "argument 2 receives console bytes")}},
    {"kernel32", {"readconsolew", "ReadConsoleW",
        FixedOutput(1, Encoding::WideText, false,
                    "argument 2 receives UTF-16 console characters")}},
    {"kernelbase", {"readconsolea", "ReadConsoleA",
        FixedOutput(1, Encoding::NarrowText, false,
                    "argument 2 receives console bytes")}},
    {"kernelbase", {"readconsolew", "ReadConsoleW",
        FixedOutput(1, Encoding::WideText, false,
                    "argument 2 receives UTF-16 console characters")}},
    {"user32", {"getdlgitemtexta", "GetDlgItemTextA",
        FixedOutput(2, Encoding::NarrowText, false,
                    "argument 3 receives dialog-control text")}},
    {"user32", {"getdlgitemtextw", "GetDlgItemTextW",
        FixedOutput(2, Encoding::WideText, false,
                    "argument 3 receives UTF-16 dialog-control text")}},
    {"user32", {"getwindowtexta", "GetWindowTextA",
        FixedOutput(1, Encoding::NarrowText, false,
                    "argument 2 receives window text")}},
    {"user32", {"getwindowtextw", "GetWindowTextW",
        FixedOutput(1, Encoding::WideText, false,
                    "argument 2 receives UTF-16 window text")}},
};

constexpr ProducerSpec kFixedStdioProducers[] = {
    {"fgets", "fgets", FixedOutput(0, Encoding::NarrowText, true,
        "argument 1 receives a narrow line; success returns the same pointer")},
    {"fgetws", "fgetws", FixedOutput(0, Encoding::WideText, true,
        "argument 1 receives a wide line; success returns the same pointer")},
    {"gets", "gets", FixedOutput(0, Encoding::NarrowText, true,
        "argument 1 receives a narrow line; legacy unsafe API")},
    {"getws", "_getws", FixedOutput(0, Encoding::WideText, true,
        "argument 1 receives a wide line; legacy unsafe API")},
};

constexpr ProducerSpec kFormattedStdioProducers[] = {
    {"scanf", "scanf", FormatDriven(0, 1,
        "format argument 1 selects one or more variadic output arguments")},
    {"wscanf", "wscanf", FormatDriven(0, 1,
        "wide format argument 1 selects one or more variadic output arguments")},
};

constexpr ProducerSpec kSecureFixedStdioProducers[] = {
    {"gets_s", "gets_s", FixedOutput(0, Encoding::NarrowText, true,
        "argument 1 receives a bounded narrow line")},
    {"getws_s", "_getws_s", FixedOutput(0, Encoding::WideText, true,
        "argument 1 receives a bounded wide line")},
};

constexpr ProducerSpec kSecureFormattedStdioProducers[] = {
    {"scanf_s", "scanf_s", FormatDriven(0, 1,
        "format argument 1 selects secure variadic outputs and size arguments")},
    {"wscanf_s", "wscanf_s", FormatDriven(0, 1,
        "wide format argument 1 selects secure variadic outputs and size arguments")},
};

constexpr ProducerSpec kConioProducers[] = {
    {"cgets_s", "_cgets_s", FixedOutput(0, Encoding::NarrowText, false,
        "argument 1 receives bounded console text")},
    {"cgetws_s", "_cgetws_s", FixedOutput(0, Encoding::WideText, false,
        "argument 1 receives bounded UTF-16 console text")},
};

constexpr ComparatorSpec kCrtComparators[] = {
    {"strcmp", "strcmp", Comparator(0, 1, Encoding::NarrowText,
        EqualityRule::ZeroIsEqual, 0, "zero means the narrow strings are equal")},
    {"strncmp", "strncmp", Comparator(0, 1, Encoding::NarrowText,
        EqualityRule::ZeroIsEqual, 0, "zero means the bounded narrow strings are equal",
        true, 2)},
    {"stricmp", "_stricmp", Comparator(0, 1, Encoding::NarrowText,
        EqualityRule::ZeroIsEqual, 0, "zero means the narrow strings are equal ignoring case")},
    {"strnicmp", "_strnicmp", Comparator(0, 1, Encoding::NarrowText,
        EqualityRule::ZeroIsEqual, 0, "zero means the bounded narrow strings are equal ignoring case",
        true, 2)},
    {"wcscmp", "wcscmp", Comparator(0, 1, Encoding::WideText,
        EqualityRule::ZeroIsEqual, 0, "zero means the wide strings are equal")},
    {"wcsncmp", "wcsncmp", Comparator(0, 1, Encoding::WideText,
        EqualityRule::ZeroIsEqual, 0, "zero means the bounded wide strings are equal",
        true, 2)},
    {"wcsicmp", "_wcsicmp", Comparator(0, 1, Encoding::WideText,
        EqualityRule::ZeroIsEqual, 0, "zero means the wide strings are equal ignoring case")},
    {"wcsnicmp", "_wcsnicmp", Comparator(0, 1, Encoding::WideText,
        EqualityRule::ZeroIsEqual, 0, "zero means the bounded wide strings are equal ignoring case",
        true, 2)},
    {"memcmp", "memcmp", Comparator(0, 1, Encoding::Bytes,
        EqualityRule::ZeroIsEqual, 0, "zero means the bounded byte regions are equal",
        true, 2)},
};

constexpr DirectComparatorSpec kKernelComparators[] = {
    {"kernel32", {"lstrcmpa", "lstrcmpA", Comparator(0, 1,
        Encoding::NarrowText, EqualityRule::ZeroIsEqual, 0,
        "zero means the narrow strings are equal")}},
    {"kernel32", {"lstrcmpw", "lstrcmpW", Comparator(0, 1,
        Encoding::WideText, EqualityRule::ZeroIsEqual, 0,
        "zero means the wide strings are equal")}},
    {"kernel32", {"lstrcmpia", "lstrcmpiA", Comparator(0, 1,
        Encoding::NarrowText, EqualityRule::ZeroIsEqual, 0,
        "zero means the narrow strings are equal ignoring case")}},
    {"kernel32", {"lstrcmpiw", "lstrcmpiW", Comparator(0, 1,
        Encoding::WideText, EqualityRule::ZeroIsEqual, 0,
        "zero means the wide strings are equal ignoring case")}},
    {"kernel32", {"comparestringa", "CompareStringA", Comparator(2, 4,
        Encoding::NarrowText, EqualityRule::ExactValueIsEqual, 2,
        "CSTR_EQUAL (2) means the locale-aware narrow strings are equal",
        true, 3, true, 5)}},
    {"kernel32", {"comparestringw", "CompareStringW", Comparator(2, 4,
        Encoding::WideText, EqualityRule::ExactValueIsEqual, 2,
        "CSTR_EQUAL (2) means the locale-aware wide strings are equal",
        true, 3, true, 5)}},
    {"kernel32", {"comparestringex", "CompareStringEx", Comparator(2, 4,
        Encoding::WideText, EqualityRule::ExactValueIsEqual, 2,
        "CSTR_EQUAL (2) means the locale-aware wide strings are equal",
        true, 3, true, 5)}},
    {"kernel32", {"comparestringordinal", "CompareStringOrdinal", Comparator(0, 2,
        Encoding::WideText, EqualityRule::ExactValueIsEqual, 2,
        "CSTR_EQUAL (2) means the ordinal wide strings are equal",
        true, 1, true, 3)}},

    {"kernelbase", {"lstrcmpa", "lstrcmpA", Comparator(0, 1,
        Encoding::NarrowText, EqualityRule::ZeroIsEqual, 0,
        "zero means the narrow strings are equal")}},
    {"kernelbase", {"lstrcmpw", "lstrcmpW", Comparator(0, 1,
        Encoding::WideText, EqualityRule::ZeroIsEqual, 0,
        "zero means the wide strings are equal")}},
    {"kernelbase", {"lstrcmpia", "lstrcmpiA", Comparator(0, 1,
        Encoding::NarrowText, EqualityRule::ZeroIsEqual, 0,
        "zero means the narrow strings are equal ignoring case")}},
    {"kernelbase", {"lstrcmpiw", "lstrcmpiW", Comparator(0, 1,
        Encoding::WideText, EqualityRule::ZeroIsEqual, 0,
        "zero means the wide strings are equal ignoring case")}},
    {"kernelbase", {"comparestringa", "CompareStringA", Comparator(2, 4,
        Encoding::NarrowText, EqualityRule::ExactValueIsEqual, 2,
        "CSTR_EQUAL (2) means the locale-aware narrow strings are equal",
        true, 3, true, 5)}},
    {"kernelbase", {"comparestringw", "CompareStringW", Comparator(2, 4,
        Encoding::WideText, EqualityRule::ExactValueIsEqual, 2,
        "CSTR_EQUAL (2) means the locale-aware wide strings are equal",
        true, 3, true, 5)}},
    {"kernelbase", {"comparestringex", "CompareStringEx", Comparator(2, 4,
        Encoding::WideText, EqualityRule::ExactValueIsEqual, 2,
        "CSTR_EQUAL (2) means the locale-aware wide strings are equal",
        true, 3, true, 5)}},
    {"kernelbase", {"comparestringordinal", "CompareStringOrdinal", Comparator(0, 2,
        Encoding::WideText, EqualityRule::ExactValueIsEqual, 2,
        "CSTR_EQUAL (2) means the ordinal wide strings are equal",
        true, 1, true, 3)}},
};

constexpr DirectComparatorSpec kShlwapiComparators[] = {
    {"shlwapi", {"strcmpw", "StrCmpW", Comparator(0, 1,
        Encoding::WideText, EqualityRule::ZeroIsEqual, 0,
        "zero means the wide strings are equal")}},
    {"shlwapi", {"strcmpiw", "StrCmpIW", Comparator(0, 1,
        Encoding::WideText, EqualityRule::ZeroIsEqual, 0,
        "zero means the wide strings are equal ignoring case")}},
    {"shlwapi", {"strcmpna", "StrCmpNA", Comparator(0, 1,
        Encoding::NarrowText, EqualityRule::ZeroIsEqual, 0,
        "zero means the bounded narrow strings are equal", true, 2)}},
    {"shlwapi", {"strcmpnw", "StrCmpNW", Comparator(0, 1,
        Encoding::WideText, EqualityRule::ZeroIsEqual, 0,
        "zero means the bounded wide strings are equal", true, 2)}},
    {"shlwapi", {"strcmpnia", "StrCmpNIA", Comparator(0, 1,
        Encoding::NarrowText, EqualityRule::ZeroIsEqual, 0,
        "zero means the bounded narrow strings are equal ignoring case", true, 2)}},
    {"shlwapi", {"strcmpniw", "StrCmpNIW", Comparator(0, 1,
        Encoding::WideText, EqualityRule::ZeroIsEqual, 0,
        "zero means the bounded wide strings are equal ignoring case", true, 2)}},
};

constexpr size_t kExpectedCatalogRows =
    ArrayCount(kDirectProducers) +
    ArrayCount(kFixedStdioModules) * ArrayCount(kFixedStdioProducers) +
    ArrayCount(kFormattedStdioModules) * ArrayCount(kFormattedStdioProducers) +
    ArrayCount(kSecureFixedStdioModules) *
        ArrayCount(kSecureFixedStdioProducers) +
    ArrayCount(kSecureFormattedStdioModules) *
        ArrayCount(kSecureFormattedStdioProducers) +
    ArrayCount(kConioModules) * ArrayCount(kConioProducers) +
    ArrayCount(kStringModules) * ArrayCount(kCrtComparators) +
    ArrayCount(kKernelComparators) + ArrayCount(kShlwapiComparators);

static_assert(kExpectedCatalogRows <= kValidationApiCatalogHardMaxRows,
              "validation API catalog exceeds its hard row cap");

const std::vector<CatalogRow>& Catalog() {
    static const std::vector<CatalogRow> rows = [] {
        std::vector<CatalogRow> out;
        out.reserve(kExpectedCatalogRows);

        const auto addProducer = [&](std::string_view dll,
                                     const ProducerSpec& spec) {
            CatalogRow row;
            row.kind = ValidationApiKind::InputProducer;
            row.dll = dll;
            row.key = spec.key;
            row.canonical = spec.canonical;
            row.input = spec.contract;
            out.push_back(row);
        };
        const auto addComparator = [&](std::string_view dll,
                                       const ComparatorSpec& spec) {
            CatalogRow row;
            row.kind = ValidationApiKind::EqualityComparator;
            row.dll = dll;
            row.key = spec.key;
            row.canonical = spec.canonical;
            row.comparator = spec.contract;
            out.push_back(row);
        };

        for (const DirectProducerSpec& row : kDirectProducers)
            addProducer(row.dll, row.producer);
        for (std::string_view module : kFixedStdioModules)
            for (const ProducerSpec& spec : kFixedStdioProducers)
                addProducer(module, spec);
        for (std::string_view module : kFormattedStdioModules)
            for (const ProducerSpec& spec : kFormattedStdioProducers)
                addProducer(module, spec);
        for (std::string_view module : kSecureFixedStdioModules)
            for (const ProducerSpec& spec : kSecureFixedStdioProducers)
                addProducer(module, spec);
        for (std::string_view module : kSecureFormattedStdioModules)
            for (const ProducerSpec& spec : kSecureFormattedStdioProducers)
                addProducer(module, spec);
        for (std::string_view module : kConioModules)
            for (const ProducerSpec& spec : kConioProducers)
                addProducer(module, spec);

        for (std::string_view module : kStringModules)
            for (const ComparatorSpec& spec : kCrtComparators)
                addComparator(module, spec);
        for (const DirectComparatorSpec& row : kKernelComparators)
            addComparator(row.dll, row.comparator);
        for (const DirectComparatorSpec& row : kShlwapiComparators)
            addComparator(row.dll, row.comparator);

        return out;
    }();
    return rows;
}

constexpr bool AsciiSpace(char value) {
    return value == ' ' || value == '\t' || value == '\r' ||
           value == '\n' || value == '\f' || value == '\v';
}

std::string_view TrimView(std::string_view value) {
    size_t first = 0;
    size_t last = value.size();
    while (first < last && AsciiSpace(value[first])) ++first;
    while (last > first && AsciiSpace(value[last - 1])) --last;
    return value.substr(first, last - first);
}

char AsciiLower(char value) {
    return value >= 'A' && value <= 'Z'
         ? static_cast<char>(value + ('a' - 'A')) : value;
}

bool AllDigits(std::string_view value) {
    if (value.empty()) return false;
    for (char c : value)
        if (c < '0' || c > '9') return false;
    return true;
}

ValidationApiMatch MakeMatch(const CatalogRow& row) {
    ValidationApiMatch result;
    result.kind = row.kind;
    result.dll.assign(row.dll);
    result.canonicalName.assign(row.canonical);
    result.normalizedName.assign(row.key);
    result.input = row.input;
    result.comparator = row.comparator;
    return result;
}

} // namespace

const char* ValidationApiKindText(ValidationApiKind kind) {
    switch (kind) {
    case ValidationApiKind::InputProducer:      return "input producer";
    case ValidationApiKind::EqualityComparator:return "equality comparator";
    }
    return "unknown";
}

const char* ValidationDataEncodingText(ValidationDataEncoding encoding) {
    switch (encoding) {
    case ValidationDataEncoding::Bytes:           return "bytes";
    case ValidationDataEncoding::NarrowText:      return "narrow text";
    case ValidationDataEncoding::WideText:        return "wide text";
    case ValidationDataEncoding::FormatDependent: return "format-dependent";
    }
    return "unknown";
}

const char* ValidationInputBindingText(ValidationInputBinding binding) {
    switch (binding) {
    case ValidationInputBinding::FixedOutputArgument:
        return "fixed output argument";
    case ValidationInputBinding::FormatDrivenArguments:
        return "format-driven arguments";
    }
    return "unknown";
}

const char* ValidationEqualityRuleText(ValidationEqualityRule rule) {
    switch (rule) {
    case ValidationEqualityRule::ZeroIsEqual:       return "zero is equal";
    case ValidationEqualityRule::NonZeroIsEqual:    return "nonzero is equal";
    case ValidationEqualityRule::ExactValueIsEqual: return "exact value is equal";
    }
    return "unknown";
}

std::string NormalizeValidationDll(std::string_view dll) {
    if (dll.size() > kValidationLookupFieldMaxBytes) return {};
    dll = TrimView(dll);
    if (const size_t bang = dll.find('!'); bang != std::string_view::npos)
        dll = TrimView(dll.substr(0, bang));
    if (const size_t slash = dll.find_last_of("/\\");
        slash != std::string_view::npos)
        dll.remove_prefix(slash + 1);
    dll = TrimView(dll);
    if (dll.empty() || dll.size() > kValidationNormalizedDllMaxBytes)
        return {};

    std::string result;
    result.reserve(dll.size());
    for (char c : dll) result.push_back(AsciiLower(c));
    if (result.size() > 4 && result.ends_with(".dll"))
        result.resize(result.size() - 4);
    if (result.empty() || result.size() > kValidationNormalizedDllMaxBytes)
        return {};
    return result;
}

std::string NormalizeValidationApiName(std::string_view symbol) {
    if (symbol.size() > kValidationLookupFieldMaxBytes) return {};
    symbol = TrimView(symbol);
    if (const size_t bang = symbol.rfind('!'); bang != std::string_view::npos)
        symbol = TrimView(symbol.substr(bang + 1));
    if (symbol.empty() || symbol.size() > kValidationNormalizedSymbolMaxBytes)
        return {};

    std::string result;
    result.reserve(symbol.size());
    for (char c : symbol) result.push_back(AsciiLower(c));

    constexpr std::string_view prefixes[] = {
        "__imp__", "__imp_", "_imp__", "_imp_", "imp_",
    };
    for (size_t pass = 0; pass < 8; ++pass) {
        bool stripped = false;
        for (std::string_view prefix : prefixes) {
            if (result.starts_with(prefix)) {
                result.erase(0, prefix.size());
                stripped = true;
                break;
            }
        }
        if (!stripped) break;
    }
    while (!result.empty() &&
           (result.front() == '_' || result.front() == '@'))
        result.erase(result.begin());

    if (const size_t at = result.rfind('@');
        at != std::string::npos && AllDigits(std::string_view(result).substr(at + 1)))
        result.resize(at);

    if (result.empty() || result.size() > kValidationNormalizedSymbolMaxBytes)
        return {};
    return result;
}

std::optional<ValidationApiMatch> LookupValidationApi(
    std::string_view dll, std::string_view symbol) {
    if (dll.size() > kValidationLookupFieldMaxBytes ||
        symbol.size() > kValidationLookupFieldMaxBytes)
        return std::nullopt;

    const std::string_view suppliedDll = TrimView(dll);
    const bool moduleSupplied = !suppliedDll.empty();
    std::string module = NormalizeValidationDll(suppliedDll);
    if (moduleSupplied && module.empty()) return std::nullopt;

    const std::string_view trimmedSymbol = TrimView(symbol);
    const size_t bang = trimmedSymbol.find('!');
    if (bang != std::string_view::npos) {
        if (trimmedSymbol.find('!', bang + 1) != std::string_view::npos)
            return std::nullopt;
        const std::string qualifiedModule =
            NormalizeValidationDll(trimmedSymbol.substr(0, bang));
        if (qualifiedModule.empty()) return std::nullopt;
        if (module.empty()) module = qualifiedModule;
        else if (module != qualifiedModule) return std::nullopt;
    }
    if (module.empty()) return std::nullopt;

    const std::string name = NormalizeValidationApiName(trimmedSymbol);
    if (name.empty()) return std::nullopt;
    for (const CatalogRow& row : Catalog())
        if (row.dll == module && row.key == name) return MakeMatch(row);
    return std::nullopt;
}

std::optional<ValidationApiMatch> LookupValidationInputProducer(
    std::string_view dll, std::string_view symbol) {
    std::optional<ValidationApiMatch> result =
        LookupValidationApi(dll, symbol);
    if (!result || result->kind != ValidationApiKind::InputProducer)
        return std::nullopt;
    return result;
}

std::optional<ValidationApiMatch> LookupValidationEqualityComparator(
    std::string_view dll, std::string_view symbol) {
    std::optional<ValidationApiMatch> result =
        LookupValidationApi(dll, symbol);
    if (!result || result->kind != ValidationApiKind::EqualityComparator)
        return std::nullopt;
    return result;
}

bool ValidationComparatorResultIsEqual(
    const ValidationEqualityComparatorContract& contract,
    uint64_t rawValue) {
    const int32_t value = static_cast<int32_t>(
        static_cast<uint32_t>(rawValue));
    switch (contract.equalityRule) {
    case ValidationEqualityRule::ZeroIsEqual:
        return value == 0;
    case ValidationEqualityRule::NonZeroIsEqual:
        return value != 0;
    case ValidationEqualityRule::ExactValueIsEqual:
        return value == contract.equalityValue;
    }
    return false;
}

std::vector<ValidationApiMatch> EnumerateValidationApis() {
    std::vector<ValidationApiMatch> result;
    result.reserve(Catalog().size());
    for (const CatalogRow& row : Catalog()) result.push_back(MakeMatch(row));
    return result;
}

} // namespace ds
