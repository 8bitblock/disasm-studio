#pragma once
//
// ValidationApiCatalog.h
// Exact, bounded DLL+symbol contracts for common local crackme input producers
// and equality comparators.  A familiar symbol in an unrelated module never
// inherits a contract, and format-driven input never pretends to have one fixed
// output buffer until a later adapter has parsed the format string.
//

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

// Lookup work is bounded before allocating normalized strings. Catalog growth
// is also capped at compile time so enumeration cannot become an accidental
// unbounded surface.
inline constexpr size_t kValidationLookupFieldMaxBytes = 1024;
inline constexpr size_t kValidationNormalizedDllMaxBytes = 128;
inline constexpr size_t kValidationNormalizedSymbolMaxBytes = 256;
inline constexpr size_t kValidationApiCatalogHardMaxRows = 256;
inline constexpr size_t kValidationComparatorMaxLengthArguments = 2;

enum class ValidationApiKind : uint8_t {
    InputProducer = 0,
    EqualityComparator,
};

enum class ValidationDataEncoding : uint8_t {
    Bytes = 0,
    NarrowText,
    WideText,
    // scanf/wscanf conversions can change the destination type. A consumer
    // must parse the exact format conversion before assigning an encoding.
    FormatDependent,
};

enum class ValidationInputBinding : uint8_t {
    // The producer always writes one catalog-declared pointer argument.
    FixedOutputArgument = 0,
    // One or more output arguments are selected by a format string. No fixed
    // outputArgumentIndex is valid for this binding.
    FormatDrivenArguments,
};

enum class ValidationEqualityRule : uint8_t {
    ZeroIsEqual = 0,
    NonZeroIsEqual,
    ExactValueIsEqual,
};

const char* ValidationApiKindText(ValidationApiKind kind);
const char* ValidationDataEncodingText(ValidationDataEncoding encoding);
const char* ValidationInputBindingText(ValidationInputBinding binding);
const char* ValidationEqualityRuleText(ValidationEqualityRule rule);

struct ValidationInputProducerContract {
    ValidationInputBinding binding = ValidationInputBinding::FixedOutputArgument;

    uint8_t outputArgumentIndex = 0; // zero-based
    bool outputArgumentIndexValid = false;

    uint8_t formatArgumentIndex = 0; // zero-based
    bool formatArgumentIndexValid = false;
    uint8_t firstOutputArgumentIndex = 0; // first variadic candidate, zero-based
    bool firstOutputArgumentIndexValid = false;

    ValidationDataEncoding encoding = ValidationDataEncoding::Bytes;
    // fgets/gets return the same destination pointer on success. Win32 input
    // APIs instead return a status/count and leave this false.
    bool returnValueAliasesOutput = false;
    std::string_view meaning;
};

struct ValidationEqualityComparatorContract {
    uint8_t leftArgumentIndex = 0;  // zero-based
    uint8_t rightArgumentIndex = 1; // zero-based
    std::array<uint8_t, kValidationComparatorMaxLengthArguments>
        lengthArgumentIndices{};
    uint8_t lengthArgumentCount = 0;
    ValidationDataEncoding encoding = ValidationDataEncoding::Bytes;
    ValidationEqualityRule equalityRule = ValidationEqualityRule::ZeroIsEqual;
    // Used only by ExactValueIsEqual. Comparison returns are interpreted as a
    // signed 32-bit integer, matching the catalogued C/Win32 APIs.
    int32_t equalityValue = 0;
    std::string_view meaning;
};

struct ValidationApiMatch {
    ValidationApiKind kind = ValidationApiKind::InputProducer;
    std::string dll;            // normalized lower-case basename, no .dll
    std::string canonicalName;  // stable SDK/CRT spelling
    std::string normalizedName; // decoration-free lower-case exact key

    // Only the contract selected by kind is meaningful.
    ValidationInputProducerContract input;
    ValidationEqualityComparatorContract comparator;
};

// Keep only a bounded module basename, lower-case it, and remove a trailing
// .dll. Oversized fields normalize to an empty string.
std::string NormalizeValidationDll(std::string_view dll);

// Remove a module qualifier, common __imp decorations, one-or-more leading C
// decoration characters, and a numeric stdcall suffix. A/W suffixes are kept:
// they are semantically significant for the encoding contract.
std::string NormalizeValidationApiName(std::string_view symbol);

// Exact module+symbol lookup. A module embedded in symbol (module!name) may
// supply an omitted dll, but conflicts with a supplied dll are rejected.
std::optional<ValidationApiMatch> LookupValidationApi(
    std::string_view dll, std::string_view symbol);
std::optional<ValidationApiMatch> LookupValidationInputProducer(
    std::string_view dll, std::string_view symbol);
std::optional<ValidationApiMatch> LookupValidationEqualityComparator(
    std::string_view dll, std::string_view symbol);

// Interpret the immediate comparator return according to the exact contract.
bool ValidationComparatorResultIsEqual(
    const ValidationEqualityComparatorContract& contract,
    uint64_t rawValue);

// Deterministic fixed-catalog enumeration for candidate-owner discovery and
// coverage reporting. Its size never exceeds kValidationApiCatalogHardMaxRows.
std::vector<ValidationApiMatch> EnumerateValidationApis();

} // namespace ds
