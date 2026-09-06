#include "Core/MemoryTable.h"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <map>
#include <span>
#include <string>
#include <vector>

using namespace ds;

static int failures = 0;
#define CHECK(expr) do { if (!(expr)) { \
    std::cerr << "CHECK failed at line " << __LINE__ << ": " #expr "\n"; \
    ++failures; } } while (0)

static MemoryTableReader mapReader(const std::map<uint64_t, uint64_t>& memory,
                                   size_t pointerWidth,
                                   size_t* calls = nullptr) {
    return [&memory, pointerWidth, calls](uint64_t address, void* output,
                                          size_t size) -> size_t {
        if (calls) ++*calls;
        const auto found = memory.find(address);
        if (found == memory.end() || size != pointerWidth) return 0;
        const uint64_t value = found->second;
        for (size_t i = 0; i < size; ++i)
            static_cast<uint8_t*>(output)[i] =
                static_cast<uint8_t>(value >> (i * 8));
        return size;
    };
}

template <typename T>
static std::vector<uint8_t> bytesOf(T value) {
    std::vector<uint8_t> bytes(sizeof(value));
    std::memcpy(bytes.data(), &value, sizeof(value));
    return bytes;
}

static void replaceOnce(std::string& text, const std::string& from,
                        const std::string& to) {
    const size_t at = text.find(from);
    CHECK(at != std::string::npos);
    if (at != std::string::npos) text.replace(at, from.size(), to);
}

int main() {
    // Absolute expressions with no pointer steps need no reader.
    {
        MemoryTableAddress address;
        address.absoluteAddress = 0x12345678;
        size_t calls = 0;
        const auto result = ResolveMemoryTableAddress(
            address, {}, [&calls](uint64_t, void*, size_t) {
                ++calls;
                return size_t{0};
            }, 8);
        CHECK(result.resolved());
        CHECK(result.address == 0x12345678);
        CHECK(result.addresses == std::vector<uint64_t>{0x12345678});
        CHECK(calls == 0);
    }

    // Full path identity is preferred even when the basename is ambiguous.
    // Both slash spelling and ASCII case are normalized without filesystem I/O.
    const std::vector<MemoryTableModuleView> modules = {
        {"game.exe", "C:\\Games\\One\\game.exe", 0x100000, 0x10000},
        {"GAME.EXE", "D:\\Games\\Two\\GAME.EXE", 0x500000, 0x20000},
        {"helper.dll", "C:\\Games\\One\\helper.dll", 0x800000, 0x1000},
    };
    {
        MemoryTableAddress address;
        address.kind = MemoryTableBaseKind::ModuleRelative;
        address.moduleName = "game.exe";
        address.modulePath = "c:/games/one/GAME.EXE";
        address.moduleOffset = 0x234;
        const auto result = ResolveMemoryTableAddress(address, modules, {}, 8);
        CHECK(result.resolved());
        CHECK(result.address == 0x100234);
        CHECK(result.moduleBase == 0x100000);
        CHECK(result.moduleIndex == 0);
        CHECK(result.moduleMatchedByPath);
    }
    {
        MemoryTableAddress address;
        address.kind = MemoryTableBaseKind::ModuleRelative;
        address.moduleName = "game.exe";
        address.modulePath = "E:\\Moved\\game.exe"; // no exact path
        CHECK(ResolveMemoryTableAddress(address, modules, {}, 8).status ==
              MemoryTableResolveStatus::AmbiguousModule);

        address.moduleName = "helper.dll";
        address.modulePath.clear();
        const auto unique = ResolveMemoryTableAddress(address, modules, {}, 8);
        CHECK(unique.resolved() && unique.address == 0x800000);

        address.moduleOffset = 0x1000;
        CHECK(ResolveMemoryTableAddress(address, modules, {}, 8).status ==
              MemoryTableResolveStatus::ModuleOffsetOutsideImage);
    }
    {
        // Even exact-path duplicates fail rather than depending on enumeration
        // order (including duplicate projections of the same loaded base).
        std::vector<MemoryTableModuleView> duplicates = {
            {"same.dll", "C:\\same.dll", 0x1000, 0x100},
            {"same.dll", "c:/SAME.dll", 0x2000, 0x100},
        };
        MemoryTableAddress address;
        address.kind = MemoryTableBaseKind::ModuleRelative;
        address.modulePath = "C:\\same.dll";
        CHECK(ResolveMemoryTableAddress(address, duplicates, {}, 8).status ==
              MemoryTableResolveStatus::AmbiguousModule);
        duplicates[1].base = duplicates[0].base;
        CHECK(ResolveMemoryTableAddress(address, duplicates, {}, 8).status ==
              MemoryTableResolveStatus::AmbiguousModule);

        // A pointer root must contain a complete pointer inside the module.
        duplicates.resize(1);
        address.moduleOffset = 0xfc;
        address.pointerOffsets = {0};
        CHECK(ResolveMemoryTableAddress(address, duplicates, {}, 8).status ==
              MemoryTableResolveStatus::ModuleOffsetOutsideImage);
    }

    // Pointer chains are root-to-target, exact-read, little-endian, signed,
    // and report their successfully resolved prefix.
    {
        MemoryTableAddress address;
        address.absoluteAddress = 0x1000;
        address.pointerOffsets = {0x20, -0x10};
        const std::map<uint64_t, uint64_t> memory = {
            {0x1000, 0x2000},
            {0x2020, 0x3000},
        };
        const auto result = ResolveMemoryTableAddress(
            address, {}, mapReader(memory, 8), 8);
        CHECK(result.resolved());
        CHECK(result.address == 0x2ff0);
        CHECK(result.stepsResolved == 2);
        CHECK((result.pointerValues == std::vector<uint64_t>{0x2000, 0x3000}));
        CHECK((result.addresses ==
               std::vector<uint64_t>{0x1000, 0x2020, 0x2ff0}));

        address.pointerOffsets.push_back(0);
        const auto partial = ResolveMemoryTableAddress(
            address, {}, mapReader(memory, 8), 8);
        CHECK(partial.status == MemoryTableResolveStatus::ReadFailure);
        CHECK(partial.stepsResolved == 2 && partial.address == 0x2ff0);
    }
    {
        MemoryTableAddress address;
        address.absoluteAddress = 0x1000;
        address.pointerOffsets = {1};
        const std::map<uint64_t, uint64_t> nullMemory = {{0x1000, 0}};
        CHECK(ResolveMemoryTableAddress(address, {}, mapReader(nullMemory, 8), 8).status ==
              MemoryTableResolveStatus::NullPointer);

        const std::map<uint64_t, uint64_t> high32 = {{0x1000, 0xfffffff8u}};
        address.pointerOffsets = {16};
        CHECK(ResolveMemoryTableAddress(address, {}, mapReader(high32, 4), 4).status ==
              MemoryTableResolveStatus::ArithmeticOverflow);

        const std::map<uint64_t, uint64_t> noncanonical = {
            {0x1000, 0x0000800000000000ull}
        };
        address.pointerOffsets = {0};
        CHECK(ResolveMemoryTableAddress(
                  address, {}, mapReader(noncanonical, 8), 8).status ==
              MemoryTableResolveStatus::NonCanonicalPointer);

        CHECK(ResolveMemoryTableAddress(
                  address, {}, [](uint64_t, void*, size_t size) {
                      return size - 1;
                  }, 8).status == MemoryTableResolveStatus::ReadFailure);
        CHECK(ResolveMemoryTableAddress(
                  address, {}, [](uint64_t, void*, size_t) -> size_t {
                      throw 7;
                  }, 8).status == MemoryTableResolveStatus::ReaderException);

        CHECK(ResolveMemoryTableAddress(address, {}, {}, 3).status ==
              MemoryTableResolveStatus::InvalidPointerWidth);
        address.pointerOffsets.clear();
        address.absoluteAddress = uint64_t{1} << 32;
        CHECK(ResolveMemoryTableAddress(address, {}, {}, 4, false).status ==
              MemoryTableResolveStatus::NonCanonicalAddress);
        address.pointerOffsets.assign(kMemoryTableMaxPointerDepth + 1, 0);
        CHECK(ResolveMemoryTableAddress(address, {}, {}, 8).status ==
              MemoryTableResolveStatus::PointerDepthLimit);
    }

    // Constant mode compares exact bytes, while runtime authority requires both
    // switches. Hex input is interpreted as a width-exact bit pattern.
    {
        MemoryTableRecord record;
        record.type = MemoryValueType::UInt32;
        record.displayHex = true;
        record.desiredValueText = "AABBCCDD";
        record.freezeMode = MemoryFreezeMode::Constant;
        std::vector<uint8_t> current = {0, 0, 0, 0};
        CHECK(EvaluateMemoryFreeze(record, current).code ==
              MemoryFreezeDecisionCode::Inactive);
        record.enabled = true;
        CHECK(EvaluateMemoryFreeze(record, current).code ==
              MemoryFreezeDecisionCode::Inactive);
        record.freezeActive = true;
        const auto write = EvaluateMemoryFreeze(record, current);
        CHECK(write.shouldWrite());
        CHECK((write.bytes == std::vector<uint8_t>{0xDD, 0xCC, 0xBB, 0xAA}));
        CHECK(EvaluateMemoryFreeze(record, write.bytes).code ==
              MemoryFreezeDecisionCode::AlreadySatisfied);
    }

    // Signed and unsigned bounds use the declared type, never host casts.
    {
        const std::vector<uint8_t> minus128 = {0x80};
        const std::vector<uint8_t> minus1 = {0xff};
        auto signedMin = EvaluateMemoryFreezeValue(
            MemoryValueType::Int8, MemoryFreezeMode::Minimum, false,
            "-1", minus128);
        CHECK(signedMin.shouldWrite() && signedMin.bytes[0] == 0xff);
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::Int8, MemoryFreezeMode::Minimum, false,
                  "-1", minus1).code ==
              MemoryFreezeDecisionCode::AlreadySatisfied);

        // 0xff is 255 for UInt8 and therefore already above a minimum of 200.
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::UInt8, MemoryFreezeMode::Minimum, false,
                  "200", minus1).code ==
              MemoryFreezeDecisionCode::AlreadySatisfied);
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::UInt8, MemoryFreezeMode::Maximum, false,
                  "200", minus1).shouldWrite());

        const auto zero64 = bytesOf<int64_t>(0);
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::Int64, MemoryFreezeMode::Maximum, false,
                  "-9223372036854775808", zero64).shouldWrite());
    }

    // Float bounds have explicit NaN/infinity behavior and constant mode keeps
    // bit identity (including the sign of zero).
    {
        const auto one = bytesOf(1.0f);
        auto minimum = EvaluateMemoryFreezeValue(
            MemoryValueType::Float32, MemoryFreezeMode::Minimum, false,
            "1.5", one);
        CHECK(minimum.shouldWrite());
        float written = 0;
        std::memcpy(&written, minimum.bytes.data(), sizeof(written));
        CHECK(written == 1.5f);

        const auto nan = bytesOf((std::numeric_limits<float>::quiet_NaN)());
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::Float32, MemoryFreezeMode::Minimum, false,
                  "1.5", nan).shouldWrite());
        const auto infinity = bytesOf((std::numeric_limits<double>::infinity)());
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::Float64, MemoryFreezeMode::Maximum, false,
                  "2", infinity).shouldWrite());

        const auto negativeZero = bytesOf(-0.0f);
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::Float32, MemoryFreezeMode::Constant, false,
                  "0", negativeZero).shouldWrite());
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::Float32, MemoryFreezeMode::Minimum, false,
                  "bits:0x7FC00000", one).code ==
              MemoryFreezeDecisionCode::InvalidDesiredValue);
    }
    {
        const std::vector<uint8_t> shortValue = {0};
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::UInt32, MemoryFreezeMode::Constant, false,
                  "7", shortValue).code ==
              MemoryFreezeDecisionCode::InvalidCurrentValue);
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::Utf8, MemoryFreezeMode::Minimum, false,
                  "hello", std::vector<uint8_t>{'h','e','l','l','o'}).code ==
              MemoryFreezeDecisionCode::InvalidDesiredValue);
        CHECK(EvaluateMemoryFreezeValue(
                  MemoryValueType::ByteArray, MemoryFreezeMode::Constant, false,
                  "AA ??", std::vector<uint8_t>{0xaa, 0xbb}).code ==
              MemoryFreezeDecisionCode::InvalidDesiredValue);
    }

    // Text freeze/write encoding preserves the explicit trailing-NUL choice.
    {
        const std::vector<uint8_t> current = {'h', 'i', 'x'};
        const auto decision = EvaluateMemoryFreezeValue(
            MemoryValueType::Utf8, MemoryFreezeMode::Constant, false,
            "hi", current, true);
        CHECK(decision.shouldWrite());
        CHECK((decision.bytes == std::vector<uint8_t>{'h', 'i', 0}));

        MemoryTableRecord invalid;
        invalid.type = MemoryValueType::UInt32;
        invalid.nullTerminateText = true;
        invalid.desiredValueText = "1";
        MemoryTableDocument invalidDocument;
        invalidDocument.records.push_back(invalid);
        std::string invalidEncoded = "unchanged";
        CHECK(!SerializeMemoryTable(invalidDocument, invalidEncoded));
        CHECK(invalidEncoded == "unchanged");
    }

    // Every persistent field round-trips exactly, including full-width/signed
    // addresses, while live authority is always saved and loaded off.
    std::string encoded;
    {
        MemoryTableDocument document;
        document.title = "Campaign table";
        MemoryTableRecord record;
        record.description = "Player health";
        record.group = "Player/Stats";
        record.type = MemoryValueType::Int32;
        record.displayHex = false;
        record.address.kind = MemoryTableBaseKind::ModuleRelative;
        record.address.moduleName = "game.exe";
        record.address.modulePath = "C:\\Games\\game.exe";
        record.address.moduleOffset = UINT64_MAX;
        record.address.pointerOffsets = {
            (std::numeric_limits<int64_t>::min)(), 0x1234
        };
        record.desiredValueText = "100";
        record.freezeMode = MemoryFreezeMode::Minimum;
        record.allowProtectionChange = true;
        record.enabled = true;
        record.freezeActive = true;
        document.records.push_back(record);

        std::string error;
        CHECK(SerializeMemoryTable(document, encoded, &error));
        CHECK(error.empty());
        CHECK(encoded.find("0xFFFFFFFFFFFFFFFF") != std::string::npos);
        CHECK(encoded.find("-0x8000000000000000") != std::string::npos);
        CHECK(encoded.find("\"enabled\": false") != std::string::npos);
        CHECK(encoded.find("\"freeze_active\": false") != std::string::npos);

        MemoryTableDocument parsed;
        const bool loadedOk = DeserializeMemoryTable(encoded, parsed, &error);
        CHECK(loadedOk);
        CHECK(parsed.title == document.title && parsed.records.size() == 1);
        if (loadedOk && parsed.records.size() == 1) {
            const auto& loaded = parsed.records[0];
            CHECK(loaded.description == record.description);
            CHECK(loaded.group == record.group);
            CHECK(loaded.type == record.type && !loaded.displayHex);
            CHECK(loaded.address.kind == MemoryTableBaseKind::ModuleRelative);
            CHECK(loaded.address.moduleName == record.address.moduleName);
            CHECK(loaded.address.modulePath == record.address.modulePath);
            CHECK(loaded.address.moduleOffset == UINT64_MAX);
            CHECK(loaded.address.pointerOffsets == record.address.pointerOffsets);
            CHECK(loaded.desiredValueText == "100");
            CHECK(loaded.freezeMode == MemoryFreezeMode::Minimum);
            CHECK(loaded.allowProtectionChange);
        CHECK(!loaded.enabled && !loaded.freezeActive);
    }

    {
        MemoryTableDocument textDocument;
        MemoryTableRecord text;
        text.description = "Player name";
        text.type = MemoryValueType::Utf16Le;
        text.nullTerminateText = true;
        text.desiredValueText = "Ada";
        textDocument.records.push_back(text);
        std::string textEncoded;
        CHECK(SerializeMemoryTable(textDocument, textEncoded));
        CHECK(textEncoded.find("\"null_terminate_text\": true") !=
              std::string::npos);
        MemoryTableDocument textParsed;
        CHECK(DeserializeMemoryTable(textEncoded, textParsed));
        CHECK(textParsed.records.size() == 1);
        if (textParsed.records.size() == 1)
            CHECK(textParsed.records[0].nullTerminateText);
    }
    }
    {
        std::string hostile = encoded;
        replaceOnce(hostile, "\"enabled\": false", "\"enabled\": true");
        replaceOnce(hostile, "\"freeze_active\": false",
                    "\"freeze_active\": true");
        // Unknown legacy authority-looking spellings cannot acquire authority.
        replaceOnce(hostile, "\"enabled\": true",
                    "\"legacy_active\": true,\n      \"enabled\": true");
        replaceOnce(hostile, "\"freeze_active\": true",
                    "\"legacy_frozen\": true,\n      \"freeze_active\": true");
        MemoryTableDocument parsed;
        const bool hostileOk = DeserializeMemoryTable(hostile, parsed);
        CHECK(hostileOk);
        if (hostileOk && parsed.records.size() == 1)
            CHECK(!parsed.records[0].enabled && !parsed.records[0].freezeActive);
    }

    // Malformed known fields, unsafe configurations, hostile bounds, and future
    // versions fail atomically without modifying the caller's current table.
    {
        MemoryTableDocument sentinel;
        sentinel.title = "unchanged";
        std::string malformed = encoded;
        replaceOnce(malformed, "\"version\": 1", "\"version\": 2");
        CHECK(!DeserializeMemoryTable(malformed, sentinel));
        CHECK(sentinel.title == "unchanged" && sentinel.records.empty());

        malformed = encoded;
        replaceOnce(malformed, "\"type\": \"int32\"",
                    "\"type\": \"imaginary\"");
        CHECK(!DeserializeMemoryTable(malformed, sentinel));
        CHECK(sentinel.title == "unchanged");

        CHECK(!DeserializeMemoryTable(
            std::string(kMemoryTableMaxSerializedBytes + 1, 'x'), sentinel));

        MemoryTableDocument invalid;
        MemoryTableRecord wildcard;
        wildcard.type = MemoryValueType::ByteArray;
        wildcard.desiredValueText = "AA ??";
        wildcard.freezeMode = MemoryFreezeMode::Constant;
        invalid.records.push_back(wildcard);
        std::string untouched = "sentinel";
        CHECK(!SerializeMemoryTable(invalid, untouched));
        CHECK(untouched == "sentinel");
    }

    if (failures) {
        std::cerr << failures << " memory-table test(s) failed\n";
        return 1;
    }
    std::cout << "memory_table_test: all checks passed\n";
    return 0;
}
