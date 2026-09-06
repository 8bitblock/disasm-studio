#include "Core/ValidationApiCatalog.h"

#include <cstdio>
#include <set>
#include <string>
#include <vector>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

int main() {
    CHECK(NormalizeValidationDll(
              " C:\\Windows\\System32\\USER32.DLL ") == "user32");
    CHECK(NormalizeValidationDll("KERNEL32.DLL!ReadConsoleW") == "kernel32");
    CHECK(NormalizeValidationApiName(
              "KERNEL32.dll!__imp__ReadConsoleW@20") == "readconsolew");
    CHECK(NormalizeValidationApiName("__imp___stricmp") == "stricmp");
    CHECK(NormalizeValidationApiName("@memcmp@12") == "memcmp");
    CHECK(NormalizeValidationApiName("ReadConsoleW") !=
          NormalizeValidationApiName("ReadConsoleA"));

    const auto dialog = LookupValidationInputProducer(
        "USER32.dll", "__imp__GetDlgItemTextW@16");
    CHECK(dialog && dialog->kind == ValidationApiKind::InputProducer);
    CHECK(dialog && dialog->canonicalName == "GetDlgItemTextW");
    CHECK(dialog && dialog->input.binding ==
                        ValidationInputBinding::FixedOutputArgument);
    CHECK(dialog && dialog->input.outputArgumentIndexValid &&
          dialog->input.outputArgumentIndex == 2);
    CHECK(dialog && dialog->input.encoding == ValidationDataEncoding::WideText);
    CHECK(dialog && !dialog->input.returnValueAliasesOutput);

    const auto console = LookupValidationInputProducer(
        "", "C:\\Windows\\System32\\KERNEL32.dll!ReadConsoleA");
    CHECK(console && console->dll == "kernel32");
    CHECK(console && console->input.outputArgumentIndexValid &&
          console->input.outputArgumentIndex == 1);
    CHECK(console && console->input.encoding ==
                         ValidationDataEncoding::NarrowText);

    const auto fgets = LookupValidationInputProducer(
        "ucrtbase.dll", "__imp__fgets");
    CHECK(fgets && fgets->input.outputArgumentIndexValid &&
          fgets->input.outputArgumentIndex == 0);
    CHECK(fgets && fgets->input.returnValueAliasesOutput);
    CHECK(fgets && fgets->input.encoding == ValidationDataEncoding::NarrowText);

    const auto getws = LookupValidationInputProducer(
        "msvcr100.dll", "__imp___getws_s");
    CHECK(getws && getws->canonicalName == "_getws_s");
    CHECK(getws && getws->input.outputArgumentIndex == 0);
    CHECK(getws && getws->input.encoding == ValidationDataEncoding::WideText);

    const auto conio = LookupValidationInputProducer(
        "api-ms-win-crt-conio-l1-1-0.dll", "_cgetws_s");
    CHECK(conio && conio->input.outputArgumentIndexValid &&
          conio->input.outputArgumentIndex == 0);
    CHECK(conio && !conio->input.returnValueAliasesOutput);

    // scanf-family rows identify the format boundary without claiming that a
    // particular variadic argument is a text buffer. That requires parsing the
    // exact conversion, including suppression and secure size arguments.
    const auto scanf = LookupValidationInputProducer(
        "msvcr120.dll", "__imp__scanf");
    CHECK(scanf && scanf->input.binding ==
                       ValidationInputBinding::FormatDrivenArguments);
    CHECK(scanf && !scanf->input.outputArgumentIndexValid);
    CHECK(scanf && scanf->input.formatArgumentIndexValid &&
          scanf->input.formatArgumentIndex == 0);
    CHECK(scanf && scanf->input.firstOutputArgumentIndexValid &&
          scanf->input.firstOutputArgumentIndex == 1);
    CHECK(scanf && scanf->input.encoding ==
                       ValidationDataEncoding::FormatDependent);

    const auto strcmp = LookupValidationEqualityComparator(
        "msvcrt.dll", "__imp__strcmp");
    CHECK(strcmp && strcmp->kind == ValidationApiKind::EqualityComparator);
    CHECK(strcmp && strcmp->comparator.leftArgumentIndex == 0 &&
          strcmp->comparator.rightArgumentIndex == 1);
    CHECK(strcmp && strcmp->comparator.lengthArgumentCount == 0);
    CHECK(strcmp && strcmp->comparator.encoding ==
                        ValidationDataEncoding::NarrowText);
    CHECK(strcmp && strcmp->comparator.equalityRule ==
                        ValidationEqualityRule::ZeroIsEqual);
    CHECK(strcmp && ValidationComparatorResultIsEqual(strcmp->comparator, 0));
    CHECK(strcmp && !ValidationComparatorResultIsEqual(strcmp->comparator, 1));
    CHECK(strcmp && !ValidationComparatorResultIsEqual(
                        strcmp->comparator, UINT64_C(0xFFFFFFFF)));

    const auto wcsncmp = LookupValidationEqualityComparator(
        "ucrtbase", "__imp__wcsncmp");
    CHECK(wcsncmp && wcsncmp->comparator.encoding ==
                         ValidationDataEncoding::WideText);
    CHECK(wcsncmp && wcsncmp->comparator.lengthArgumentCount == 1);
    CHECK(wcsncmp && wcsncmp->comparator.lengthArgumentIndices[0] == 2);

    const auto memcmp = LookupValidationEqualityComparator(
        "api-ms-win-crt-string-l1-1-0", "memcmp");
    CHECK(memcmp && memcmp->comparator.encoding == ValidationDataEncoding::Bytes);
    CHECK(memcmp && memcmp->comparator.lengthArgumentCount == 1 &&
          memcmp->comparator.lengthArgumentIndices[0] == 2);

    // CompareString uses CSTR_EQUAL (2), not strcmp's zero-is-equal rule. Its
    // two string/length pairs are retained exactly by zero-based ordinal.
    const auto compareString = LookupValidationEqualityComparator(
        "kernelbase.dll", "__imp__CompareStringW@24");
    CHECK(compareString && compareString->comparator.leftArgumentIndex == 2 &&
          compareString->comparator.rightArgumentIndex == 4);
    CHECK(compareString && compareString->comparator.lengthArgumentCount == 2);
    CHECK(compareString && compareString->comparator.lengthArgumentIndices[0] == 3 &&
          compareString->comparator.lengthArgumentIndices[1] == 5);
    CHECK(compareString && compareString->comparator.equalityRule ==
                              ValidationEqualityRule::ExactValueIsEqual);
    CHECK(compareString && compareString->comparator.equalityValue == 2);
    CHECK(compareString && ValidationComparatorResultIsEqual(
                              compareString->comparator, 2));
    CHECK(compareString && !ValidationComparatorResultIsEqual(
                              compareString->comparator, 0));
    CHECK(compareString && !ValidationComparatorResultIsEqual(
                              compareString->comparator, 1));
    CHECK(compareString && !ValidationComparatorResultIsEqual(
                              compareString->comparator, 3));

    const auto ordinal = LookupValidationEqualityComparator(
        "kernel32", "CompareStringOrdinal");
    CHECK(ordinal && ordinal->comparator.leftArgumentIndex == 0 &&
          ordinal->comparator.rightArgumentIndex == 2);
    CHECK(ordinal && ordinal->comparator.lengthArgumentCount == 2 &&
          ordinal->comparator.lengthArgumentIndices[0] == 1 &&
          ordinal->comparator.lengthArgumentIndices[1] == 3);

    const auto shellCompare = LookupValidationEqualityComparator(
        "shlwapi.dll", "StrCmpNIW");
    CHECK(shellCompare && shellCompare->comparator.encoding ==
                            ValidationDataEncoding::WideText);
    CHECK(shellCompare && shellCompare->comparator.lengthArgumentCount == 1 &&
          shellCompare->comparator.lengthArgumentIndices[0] == 2);

    ValidationEqualityComparatorContract nonzero;
    nonzero.equalityRule = ValidationEqualityRule::NonZeroIsEqual;
    CHECK(!ValidationComparatorResultIsEqual(nonzero, 0));
    CHECK(ValidationComparatorResultIsEqual(nonzero, 1));

    // Exact DLL identity and whole-symbol matching block common false positives.
    CHECK(!LookupValidationApi("user32", "strcmp"));
    CHECK(!LookupValidationApi("ucrtbase", "GetDlgItemTextW"));
    CHECK(!LookupValidationApi("kernel32", "fgets"));
    CHECK(!LookupValidationApi("evil.dll", "ReadConsoleW"));
    CHECK(!LookupValidationApi("user32", "SendMessageW"));
    CHECK(!LookupValidationApi("kernel32", "ReadConsoleWorker"));
    CHECK(!LookupValidationApi("msvcrt", "my_strcmp"));
    CHECK(!LookupValidationApi("", "strcmp"));
    CHECK(!LookupValidationApi("kernel32",
                               "kernelbase!ReadConsoleW"));
    CHECK(!LookupValidationApi("kernel32",
                               "kernel32!other!ReadConsoleW"));
    CHECK(!LookupValidationInputProducer("msvcrt", "strcmp"));
    CHECK(!LookupValidationEqualityComparator("ucrtbase", "fgets"));
    CHECK(!LookupValidationInputProducer("msvcrt", "gets_s"));
    CHECK(!LookupValidationInputProducer("msvcrt", "_getws_s"));
    CHECK(!LookupValidationInputProducer("ucrtbase", "scanf"));
    CHECK(!LookupValidationInputProducer("ucrtbase", "wscanf"));
    CHECK(!LookupValidationInputProducer("ucrtbase", "scanf_s"));
    CHECK(!LookupValidationInputProducer("ucrtbase", "wscanf_s"));
    CHECK(!LookupValidationInputProducer(
        "api-ms-win-crt-stdio-l1-1-0", "scanf"));
    CHECK(!LookupValidationInputProducer(
        "api-ms-win-crt-stdio-l1-1-0", "wscanf"));
    CHECK(!LookupValidationInputProducer(
        "api-ms-win-crt-stdio-l1-1-0", "scanf_s"));
    CHECK(!LookupValidationInputProducer(
        "api-ms-win-crt-stdio-l1-1-0", "wscanf_s"));
    CHECK(LookupValidationInputProducer("msvcr120", "scanf_s"));
    CHECK(!LookupValidationEqualityComparator("ucrtbase", "_strcmpi"));
    CHECK(!LookupValidationEqualityComparator("shlwapi", "StrCmpA"));
    CHECK(!LookupValidationEqualityComparator("shlwapi", "StrCmpIA"));
    CHECK(LookupValidationEqualityComparator("ucrtbase", "_stricmp"));
    CHECK(LookupValidationEqualityComparator("shlwapi", "StrCmpW"));
    CHECK(LookupValidationEqualityComparator("kernel32", "lstrcmpA"));

    const std::string oversizedField(kValidationLookupFieldMaxBytes + 1, 'x');
    const std::string oversizedDll(kValidationNormalizedDllMaxBytes + 1, 'd');
    const std::string oversizedSymbol(
        kValidationNormalizedSymbolMaxBytes + 1, 's');
    CHECK(NormalizeValidationDll(oversizedField).empty());
    CHECK(NormalizeValidationApiName(oversizedField).empty());
    CHECK(NormalizeValidationDll(oversizedDll).empty());
    CHECK(NormalizeValidationApiName(oversizedSymbol).empty());
    CHECK(!LookupValidationApi(oversizedField, "strcmp"));
    CHECK(!LookupValidationApi("msvcrt", oversizedField));

    const std::vector<ValidationApiMatch> catalog = EnumerateValidationApis();
    CHECK(catalog.size() >= 200);
    CHECK(catalog.size() <= kValidationApiCatalogHardMaxRows);
    std::set<std::string> uniqueKeys;
    for (const ValidationApiMatch& row : catalog) {
        CHECK(!row.dll.empty());
        CHECK(!row.canonicalName.empty());
        CHECK(!row.normalizedName.empty());
        CHECK(row.dll.size() <= kValidationNormalizedDllMaxBytes);
        CHECK(row.normalizedName.size() <= kValidationNormalizedSymbolMaxBytes);
        CHECK(uniqueKeys.insert(row.dll + "!" + row.normalizedName).second);
        const auto roundTrip = LookupValidationApi(row.dll, row.canonicalName);
        CHECK(roundTrip && roundTrip->kind == row.kind);
        CHECK(roundTrip && roundTrip->normalizedName == row.normalizedName);
        CHECK(std::string(ValidationApiKindText(row.kind)) != "unknown");

        if (row.kind == ValidationApiKind::InputProducer) {
            CHECK(!row.input.meaning.empty());
            CHECK(std::string(ValidationInputBindingText(row.input.binding)) !=
                  "unknown");
            CHECK(std::string(ValidationDataEncodingText(row.input.encoding)) !=
                  "unknown");
            if (row.input.binding ==
                ValidationInputBinding::FixedOutputArgument) {
                CHECK(row.input.outputArgumentIndexValid);
                CHECK(!row.input.formatArgumentIndexValid);
            } else {
                CHECK(!row.input.outputArgumentIndexValid);
                CHECK(row.input.formatArgumentIndexValid);
                CHECK(row.input.firstOutputArgumentIndexValid);
            }
        } else {
            CHECK(!row.comparator.meaning.empty());
            CHECK(row.comparator.lengthArgumentCount <=
                  kValidationComparatorMaxLengthArguments);
            CHECK(std::string(ValidationDataEncodingText(
                      row.comparator.encoding)) != "unknown");
            CHECK(std::string(ValidationEqualityRuleText(
                      row.comparator.equalityRule)) != "unknown");
        }
    }

    if (failures) return 1;
    std::puts("validation API catalog tests passed");
    return 0;
}
