// Pure MemoryScan value-codec, predicate, bitmap, and paging regression tests.
#include "Core/MemoryScan.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static MemoryScanValue parseValue(MemoryValueType type, const char* text,
                                  bool hex = false, bool terminator = false) {
    MemoryScanValue value;
    MemoryValueParseOptions options;
    options.hexadecimal = hex;
    options.nullTerminateText = terminator;
    std::string error;
    CHECK(ParseMemoryScanValue(type, text, options, value, &error));
    CHECK(error.empty());
    return value;
}

static MemoryScanConfig config(MemoryValueType type, MemoryScanMode mode,
                               const char* first = nullptr,
                               const char* second = nullptr) {
    MemoryScanConfig result;
    result.type = type;
    result.mode = mode;
    if (first) result.value = parseValue(type, first);
    if (second) result.secondValue = parseValue(type, second);
    return result;
}

static std::vector<uint8_t> u32s(std::initializer_list<uint32_t> values) {
    std::vector<uint8_t> out;
    for (uint32_t value : values) {
        out.push_back(static_cast<uint8_t>(value));
        out.push_back(static_cast<uint8_t>(value >> 8));
        out.push_back(static_cast<uint8_t>(value >> 16));
        out.push_back(static_cast<uint8_t>(value >> 24));
    }
    return out;
}

static bool predicate(const MemoryScanConfig& cfg,
                      const std::vector<uint8_t>& current,
                      const std::vector<uint8_t>& previous = {}) {
    return MemoryScanPredicate(cfg, current.data(), current.size(),
                               previous.empty() ? nullptr : previous.data(),
                               previous.size());
}

static void codecTests() {
    std::string error;
    MemoryScanValue untouched = parseValue(MemoryValueType::UInt8, "7");
    MemoryScanValue candidate = untouched;
    CHECK(!ParseMemoryScanValue(MemoryValueType::UInt8, "256", candidate, &error));
    CHECK(candidate.bytes == untouched.bytes); // failure is transactional
    CHECK(!error.empty());
    CHECK(!ParseMemoryScanValue(MemoryValueType::UInt8, "-1", candidate));

    const MemoryScanValue u8 = parseValue(MemoryValueType::UInt8, "255");
    CHECK(u8.bytes == std::vector<uint8_t>{0xFF});
    CHECK(FormatMemoryScanValue(u8) == "255");
    const MemoryScanValue i8 = parseValue(MemoryValueType::Int8, "-128");
    CHECK(i8.bytes == std::vector<uint8_t>{0x80});
    CHECK(FormatMemoryScanValue(i8) == "-128");
    CHECK(!ParseMemoryScanValue(MemoryValueType::Int8, "128", candidate));

    const MemoryScanValue u64 = parseValue(
        MemoryValueType::UInt64, "18446744073709551615");
    CHECK(FormatMemoryScanValue(u64) == "18446744073709551615");
    const MemoryScanValue i64 = parseValue(
        MemoryValueType::Int64, "-9223372036854775808");
    CHECK(FormatMemoryScanValue(i64) == "-9223372036854775808");

    const MemoryScanValue rawI32 = parseValue(MemoryValueType::Int32,
                                               "0xFFFFFFFF", true);
    CHECK(FormatMemoryScanValue(rawI32) == "-1");
    MemoryValueFormatOptions hexFormat;
    hexFormat.hexadecimal = true;
    CHECK(FormatMemoryScanValue(rawI32, hexFormat) == "0xFFFFFFFF");

    // max_digits10 formatting must recreate the exact IEEE bytes, including -0.
    for (const auto& item : {
             parseValue(MemoryValueType::Float32, "1.23456776"),
             parseValue(MemoryValueType::Float32, "0x80000000", true) }) {
        const std::string formatted = FormatMemoryScanValue(item);
        MemoryScanValue reparsed;
        CHECK(ParseMemoryScanValue(MemoryValueType::Float32, formatted, reparsed));
        CHECK(reparsed.bytes == item.bytes);
    }
    const MemoryScanValue preciseDouble = parseValue(
        MemoryValueType::Float64, "1.0000000000000002");
    MemoryScanValue reparsedDouble;
    CHECK(ParseMemoryScanValue(MemoryValueType::Float64,
                               FormatMemoryScanValue(preciseDouble), reparsedDouble));
    CHECK(reparsedDouble.bytes == preciseDouble.bytes);

    // Non-finite target bytes still have a lossless raw-bit spelling.
    const MemoryScanValue nanBits = parseValue(MemoryValueType::Float32,
                                                "0x7FC01234", true);
    CHECK(FormatMemoryScanValue(nanBits) == "bits:0x7FC01234");
    MemoryScanValue nanRoundTrip;
    CHECK(ParseMemoryScanValue(MemoryValueType::Float32,
                               FormatMemoryScanValue(nanBits), nanRoundTrip));
    CHECK(nanRoundTrip.bytes == nanBits.bytes);
    CHECK(!ParseMemoryScanValue(MemoryValueType::Float32, "nan", candidate));

    const MemoryScanValue pattern = parseValue(
        MemoryValueType::ByteArray, "DE AD ?? ef");
    CHECK(pattern.bytes == std::vector<uint8_t>({0xDE, 0xAD, 0x00, 0xEF}));
    CHECK(pattern.mask == std::vector<uint8_t>({0xFF, 0xFF, 0x00, 0xFF}));
    CHECK(FormatMemoryScanValue(pattern) == "DE AD ?? EF");
    CHECK(parseValue(MemoryValueType::ByteArray, "0xDEADBEEF").bytes ==
          std::vector<uint8_t>({0xDE, 0xAD, 0xBE, 0xEF}));
    CHECK(!ParseMemoryScanValue(MemoryValueType::ByteArray, "A", candidate));

    const char utf8Text[] = "A\xF0\x9F\x98\x80"; // A + U+1F600
    const MemoryScanValue utf8 = parseValue(MemoryValueType::Utf8, utf8Text,
                                             false, true);
    CHECK(utf8.nullTerminated && utf8.bytes.back() == 0);
    CHECK(FormatMemoryScanValue(utf8) == utf8Text);
    const MemoryScanValue utf16 = parseValue(MemoryValueType::Utf16Le, utf8Text,
                                              false, true);
    CHECK(utf16.bytes == std::vector<uint8_t>({
        0x41, 0x00, 0x3D, 0xD8, 0x00, 0xDE, 0x00, 0x00 }));
    CHECK(FormatMemoryScanValue(utf16) == utf8Text);
    const char invalidUtf8[] = { char(0xC0), char(0xAF), 0 };
    CHECK(!ParseMemoryScanValue(MemoryValueType::Utf8, invalidUtf8, candidate));
}

static void predicateTests() {
    const auto five = u32s({5});
    const auto ten = u32s({10});
    const auto fifteen = u32s({15});

    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::Exact, "10"), ten));
    CHECK(!predicate(config(MemoryValueType::UInt32, MemoryScanMode::Exact, "10"), five));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::NotEqual, "10"), five));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::GreaterThanValue, "10"), fifteen));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::LessThanValue, "10"), five));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::Between, "5", "15"), ten));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::Between, "5", "15"), five));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::Between, "5", "15"), fifteen));

    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::Changed), fifteen, ten));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::Unchanged), ten, ten));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::Increased), fifteen, ten));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::Decreased), five, ten));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::IncreasedBy, "5"), fifteen, ten));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::DecreasedBy, "5"), five, ten));
    CHECK(predicate(config(MemoryValueType::UInt32, MemoryScanMode::UnknownInitial), ten));

    // Integer comparisons never lose qword precision through a double conversion.
    const auto qLo = parseValue(MemoryValueType::UInt64, "9007199254740992");
    const auto qHi = parseValue(MemoryValueType::UInt64, "9007199254740993");
    MemoryScanConfig qGreater;
    qGreater.type = MemoryValueType::UInt64;
    qGreater.mode = MemoryScanMode::GreaterThanValue;
    qGreater.value = qLo;
    CHECK(MemoryScanPredicate(qGreater, qHi.bytes.data(), qHi.bytes.size(), nullptr, 0));

    // Signed types use signed ordering.
    const auto minusOne = parseValue(MemoryValueType::Int32, "-1");
    MemoryScanConfig signedLess = config(MemoryValueType::Int32,
                                         MemoryScanMode::LessThanValue, "0");
    CHECK(MemoryScanPredicate(signedLess, minusOne.bytes.data(),
                              minusOne.bytes.size(), nullptr, 0));

    // Relative integer arithmetic rejects wrapping matches.
    MemoryScanConfig overflow = config(MemoryValueType::UInt8,
                                       MemoryScanMode::IncreasedBy, "10");
    const auto four8 = parseValue(MemoryValueType::UInt8, "4");
    const auto twoFifty8 = parseValue(MemoryValueType::UInt8, "250");
    CHECK(!MemoryScanPredicate(overflow, four8.bytes.data(), four8.bytes.size(),
                               twoFifty8.bytes.data(), twoFifty8.bytes.size()));

    MemoryScanConfig tolerant = config(MemoryValueType::Float64,
                                       MemoryScanMode::Exact, "100");
    tolerant.tolerance = { true, 0.001, 0.0 };
    const auto close = parseValue(MemoryValueType::Float64, "100.0005");
    CHECK(MemoryScanPredicate(tolerant, close.bytes.data(), close.bytes.size(),
                              nullptr, 0));
    tolerant.mode = MemoryScanMode::GreaterThanValue;
    CHECK(!MemoryScanPredicate(tolerant, close.bytes.data(), close.bytes.size(),
                               nullptr, 0));
    tolerant.mode = MemoryScanMode::Changed;
    const auto base = parseValue(MemoryValueType::Float64, "100");
    CHECK(!MemoryScanPredicate(tolerant, close.bytes.data(), close.bytes.size(),
                               base.bytes.data(), base.bytes.size()));

    MemoryScanConfig wildcard;
    wildcard.type = MemoryValueType::ByteArray;
    wildcard.mode = MemoryScanMode::Exact;
    wildcard.value = parseValue(MemoryValueType::ByteArray, "DE ?? BE EF");
    const std::vector<uint8_t> bytes = {0xDE, 0x11, 0xBE, 0xEF};
    CHECK(predicate(wildcard, bytes));

    std::string error;
    MemoryScanConfig invalid = config(MemoryValueType::Utf8,
                                      MemoryScanMode::Increased);
    invalid.elementSize = 4;
    CHECK(!ValidateMemoryScanConfig(invalid, &error) && !error.empty());
    invalid = config(MemoryValueType::Int32, MemoryScanMode::IncreasedBy, "-1");
    CHECK(!ValidateMemoryScanConfig(invalid));
}

static void snapshotTests() {
    std::string error;
    // Sparse exact scans discard pages with no candidates while still pinning
    // their shape and ownership ordering for later pages.
    MemoryScanSnapshot sparse;
    MemoryScanConfig exactSeven = config(MemoryValueType::UInt8,
                                         MemoryScanMode::Exact, "7");
    CHECK(sparse.appendInitialChunk(exactSeven, 0x0800,
                                    std::vector<uint8_t>{1, 2}));
    CHECK(sparse.chunkCount() == 0 && sparse.candidateCount() == 0);
    CHECK(sparse.valueType() == MemoryValueType::UInt8 && sparse.elementSize() == 1);
    CHECK(sparse.page(0, 10).matches.empty() && !sparse.page(0, 10).hasMore);
    CHECK(!sparse.refineChunk(0, exactSeven, std::vector<uint8_t>{7, 7}));
    CHECK(!sparse.appendInitialChunk(exactSeven, 0x0801,
                                    std::vector<uint8_t>{7})); // overlaps omitted page
    CHECK(sparse.appendInitialChunk(exactSeven, 0x0802,
                                    std::vector<uint8_t>{7}));
    CHECK(sparse.chunkCount() == 1 && sparse.candidateCount() == 1);

    MemoryScanSnapshot snapshot;
    MemoryScanConfig exact = config(MemoryValueType::UInt8,
                                    MemoryScanMode::Exact, "3");
    const std::vector<uint8_t> first = {1, 3, 3, 4};
    CHECK(snapshot.appendInitialChunk(exact, 0x1000, first,
                                      MemoryScanSnapshot::kWholeSample, &error));
    CHECK(error.empty());
    CHECK(snapshot.candidateCount() == 2);
    CHECK(snapshot.chunks()[0].candidateAtOffset(1));
    CHECK(snapshot.chunks()[0].candidateAtOffset(2));
    CHECK(!snapshot.chunks()[0].candidateAtOffset(0));

    MemoryScanPage page = snapshot.page(0, 1);
    CHECK(page.total == 2 && page.matches.size() == 1 && page.hasMore);
    CHECK(page.matches[0].address == 0x1001 && page.matches[0].bytes[0] == 3);
    page = snapshot.page(page.next, 8);
    CHECK(page.matches.size() == 1 && !page.hasMore);
    CHECK(page.matches[0].address == 0x1002);

    // Alignment is based on the absolute VA, not the buffer-local offset.
    MemoryScanSnapshot aligned;
    MemoryScanConfig unknown16 = config(MemoryValueType::UInt16,
                                        MemoryScanMode::UnknownInitial);
    unknown16.alignment = 2;
    const std::vector<uint8_t> alignedBytes = {1, 2, 3, 4, 5};
    CHECK(aligned.appendInitialChunk(unknown16, 0x1001, alignedBytes, 4));
    CHECK(aligned.candidateCount() == 2);
    CHECK(aligned.chunks()[0].candidateAtOffset(1)); // 0x1002
    CHECK(aligned.chunks()[0].candidateAtOffset(3)); // 0x1004, uses lookahead

    // A chunk can own page starts while retaining lookahead; boundary matches
    // are neither missed nor duplicated by the following chunk.
    MemoryScanSnapshot boundary;
    MemoryScanConfig bytesExact;
    bytesExact.type = MemoryValueType::ByteArray;
    bytesExact.mode = MemoryScanMode::Exact;
    bytesExact.value = parseValue(MemoryValueType::ByteArray, "AA BB");
    CHECK(boundary.appendInitialChunk(bytesExact, 0x2000,
                                      std::vector<uint8_t>{0x00, 0xAA, 0xBB}, 2));
    CHECK(boundary.appendInitialChunk(bytesExact, 0x2002,
                                      std::vector<uint8_t>{0xBB}, 1));
    CHECK(boundary.candidateCount() == 1);
    CHECK(boundary.page(0, 10).matches[0].address == 0x2001);

    MemoryScanSnapshot relative;
    MemoryScanConfig unknown8 = config(MemoryValueType::UInt8,
                                       MemoryScanMode::UnknownInitial);
    CHECK(relative.appendInitialChunk(unknown8, 0x3000,
                                      std::vector<uint8_t>{10, 20, 30, 40}));
    CHECK(relative.candidateCount() == 4);
    MemoryScanConfig changed8 = config(MemoryValueType::UInt8,
                                       MemoryScanMode::Changed);
    CHECK(relative.refineChunk(0, changed8,
                               std::vector<uint8_t>{10, 25, 30, 45}));
    CHECK(relative.candidateCount() == 2);
    CHECK(relative.chunks()[0].candidateAtOffset(1));
    CHECK(relative.chunks()[0].candidateAtOffset(3));
    MemoryScanConfig increased8 = config(MemoryValueType::UInt8,
                                         MemoryScanMode::Increased);
    CHECK(relative.refineChunk(0, increased8,
                               std::vector<uint8_t>{0, 24, 0, 50}));
    CHECK(relative.candidateCount() == 1);
    CHECK(relative.page(0, 10).matches[0].address == 0x3003);
    CHECK(relative.page(0, 10).matches[0].bytes[0] == 50);

    // Paged enumeration crosses chunks without materializing the full index.
    MemoryScanSnapshot paging;
    CHECK(paging.appendInitialChunk(unknown8, 0x4000,
                                    std::vector<uint8_t>{1, 2, 3}));
    CHECK(paging.appendInitialChunk(unknown8, 0x5000,
                                    std::vector<uint8_t>{4, 5}));
    CHECK(paging.candidateCount() == 5);
    page = paging.page(2, 2);
    CHECK(page.matches.size() == 2 && page.hasMore && page.next == 4);
    CHECK(page.matches[0].address == 0x4002 && page.matches[0].bytes[0] == 3);
    CHECK(page.matches[1].address == 0x5000 && page.matches[1].bytes[0] == 4);
    page = paging.page(4, 2);
    CHECK(page.matches.size() == 1 && !page.hasMore && page.next == 5);
    CHECK(page.matches[0].address == 0x5001);

    // Failed append/refine operations leave counts and prior chunks untouched.
    CHECK(!paging.appendInitialChunk(unknown8, 0x4001,
                                     std::vector<uint8_t>{9},
                                     MemoryScanSnapshot::kWholeSample, &error));
    CHECK(paging.candidateCount() == 5);
    MemoryScanConfig wrongType = config(MemoryValueType::UInt16,
                                        MemoryScanMode::Changed);
    CHECK(!paging.refineChunk(0, wrongType, std::vector<uint8_t>{1, 2, 3}));
    CHECK(paging.candidateCount() == 5);

    // A short/failed re-read drops only candidates without a complete value.
    CHECK(paging.refineChunk(0, changed8, std::vector<uint8_t>{9}));
    CHECK(paging.candidateCount() == 3); // one changed candidate + second chunk's two
}

int main() {
    codecTests();
    predicateTests();
    snapshotTests();
    if (!g_fail) std::printf("ALL MEMORY SCAN TESTS PASSED\n");
    else std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
