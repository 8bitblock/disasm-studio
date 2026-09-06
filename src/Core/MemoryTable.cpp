#include "MemoryTable.h"

#include "Json.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

namespace ds {
namespace {

constexpr std::string_view kFormat = "DisasmStudio.MemoryTable";

void setError(std::string* error, std::string text) {
    if (error) *error = std::move(text);
}

bool noNul(std::string_view value, size_t limit) noexcept {
    return value.size() <= limit && value.find('\0') == std::string_view::npos;
}

// Count the exact bytes Json::Dump needs for string contents, without first
// materializing either its DOM copies or its escaped output. The JSON document
// has a separate final size check; this preflight specifically prevents a set
// of individually valid record strings from amplifying into an enormous DOM.
bool addEscapedStringBudget(size_t& total, std::string_view value) noexcept {
    for (const unsigned char c : value) {
        const size_t bytes = c < 0x20
            ? ((c == '\n' || c == '\r' || c == '\t' || c == '\b' || c == '\f')
                   ? 2u : 6u)
            : ((c == '"' || c == '\\') ? 2u : 1u);
        if (total > kMemoryTableMaxSerializedBytes - bytes) return false;
        total += bytes;
    }
    return true;
}

bool pathTextValid(std::string_view value, size_t limit) noexcept {
    if (!noNul(value, limit)) return false;
    for (const unsigned char c : value) {
        if (c < 0x20 || c == 0x7f) return false;
    }
    return true;
}

char asciiLower(char c) noexcept {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
}

std::string normalizePath(std::string_view path) {
    std::string result;
    result.reserve(path.size());
    for (char c : path) {
        c = asciiLower(c);
        if (c == '/') c = '\\';
        // Repeated separators carry no useful identity for a local module
        // lookup. Applying the same rule to both sides also handles UNC paths.
        if (c == '\\' && !result.empty() && result.back() == '\\') continue;
        result.push_back(c);
    }
    while (result.size() > 1 && result.back() == '\\') result.pop_back();
    // Treat the Win32 extended-length spelling as the same lexical path. This
    // is intentionally not a filesystem canonicalization (no I/O, no symlinks).
    if (result.starts_with("\\?\\unc\\")) {
        result.erase(0, 7);
        result.insert(result.begin(), '\\');
    } else if (result.starts_with("\\?\\")) {
        result.erase(0, 3);
    }
    return result;
}

std::string basenameKey(std::string_view value) {
    const size_t slash = value.find_last_of("\\/");
    if (slash != std::string_view::npos) value.remove_prefix(slash + 1);
    std::string result;
    result.reserve(value.size());
    for (char c : value) result.push_back(asciiLower(c));
    return result;
}

bool canonicalAddress(uint64_t address, uint8_t pointerWidth) noexcept {
    if (pointerWidth == 4) return address <= UINT32_MAX;
    if (pointerWidth != 8) return false;
    const uint64_t upper = address >> 48;
    const bool sign = ((address >> 47) & 1u) != 0;
    return upper == (sign ? 0xFFFFu : 0u);
}

bool readablePointerSpan(uint64_t address, uint8_t pointerWidth,
                         bool requireCanonical,
                         MemoryTableResolveStatus& failure) noexcept {
    if (address > UINT64_MAX - (pointerWidth - 1)) {
        failure = MemoryTableResolveStatus::ArithmeticOverflow;
        return false;
    }
    if (pointerWidth == 4 && address + pointerWidth - 1 > UINT32_MAX) {
        failure = MemoryTableResolveStatus::ArithmeticOverflow;
        return false;
    }
    if (requireCanonical &&
        (!canonicalAddress(address, pointerWidth) ||
         !canonicalAddress(address + pointerWidth - 1, pointerWidth))) {
        failure = MemoryTableResolveStatus::NonCanonicalAddress;
        return false;
    }
    return true;
}

bool addUnsigned(uint64_t left, uint64_t right, uint8_t pointerWidth,
                 uint64_t& result) noexcept {
    if (left > UINT64_MAX - right) return false;
    result = left + right;
    return pointerWidth != 4 || result <= UINT32_MAX;
}

bool addSigned(uint64_t left, int64_t right, uint8_t pointerWidth,
               uint64_t& result) noexcept {
    if (right >= 0)
        return addUnsigned(left, static_cast<uint64_t>(right), pointerWidth, result);
    const uint64_t magnitude =
        static_cast<uint64_t>(-(right + 1)) + uint64_t{1};
    if (left < magnitude) return false;
    result = left - magnitude;
    return pointerWidth != 4 || result <= UINT32_MAX;
}

uint64_t readLittleEndian(const uint8_t* bytes, size_t width) noexcept {
    uint64_t value = 0;
    for (size_t i = 0; i < width; ++i)
        value |= uint64_t{bytes[i]} << (i * 8);
    return value;
}

bool knownValueType(MemoryValueType type) noexcept {
    return type >= MemoryValueType::UInt8 && type <= MemoryValueType::Utf16Le;
}

bool knownFreezeMode(MemoryFreezeMode mode) noexcept {
    return mode >= MemoryFreezeMode::None && mode <= MemoryFreezeMode::Maximum;
}

std::string_view valueTypeName(MemoryValueType type) noexcept {
    switch (type) {
        case MemoryValueType::UInt8:     return "uint8";
        case MemoryValueType::Int8:      return "int8";
        case MemoryValueType::UInt16:    return "uint16";
        case MemoryValueType::Int16:     return "int16";
        case MemoryValueType::UInt32:    return "uint32";
        case MemoryValueType::Int32:     return "int32";
        case MemoryValueType::UInt64:    return "uint64";
        case MemoryValueType::Int64:     return "int64";
        case MemoryValueType::Float32:   return "float32";
        case MemoryValueType::Float64:   return "float64";
        case MemoryValueType::ByteArray: return "byte_array";
        case MemoryValueType::Utf8:      return "utf8";
        case MemoryValueType::Utf16Le:   return "utf16le";
    }
    return {};
}

bool parseValueType(std::string_view value, MemoryValueType& output) noexcept {
    for (unsigned raw = static_cast<unsigned>(MemoryValueType::UInt8);
         raw <= static_cast<unsigned>(MemoryValueType::Utf16Le); ++raw) {
        const auto candidate = static_cast<MemoryValueType>(raw);
        if (valueTypeName(candidate) == value) {
            output = candidate;
            return true;
        }
    }
    return false;
}

std::string_view freezeModeName(MemoryFreezeMode mode) noexcept {
    switch (mode) {
        case MemoryFreezeMode::None:     return "none";
        case MemoryFreezeMode::Constant: return "constant";
        case MemoryFreezeMode::Minimum:  return "minimum";
        case MemoryFreezeMode::Maximum:  return "maximum";
    }
    return {};
}

bool parseFreezeMode(std::string_view value, MemoryFreezeMode& output) noexcept {
    for (unsigned raw = static_cast<unsigned>(MemoryFreezeMode::None);
         raw <= static_cast<unsigned>(MemoryFreezeMode::Maximum); ++raw) {
        const auto candidate = static_cast<MemoryFreezeMode>(raw);
        if (freezeModeName(candidate) == value) {
            output = candidate;
            return true;
        }
    }
    return false;
}

std::string hexU64(uint64_t value) {
    char digits[16];
    const auto converted = std::to_chars(std::begin(digits), std::end(digits),
                                         value, 16);
    std::string result = "0x";
    result.append(digits, converted.ptr);
    for (char& c : result) {
        if (c >= 'a' && c <= 'f') c = static_cast<char>(c - ('a' - 'A'));
    }
    return result;
}

std::string hexI64(int64_t value) {
    if (value >= 0) return hexU64(static_cast<uint64_t>(value));
    const uint64_t magnitude =
        static_cast<uint64_t>(-(value + 1)) + uint64_t{1};
    return "-" + hexU64(magnitude);
}

int hexDigit(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool parseHexMagnitude(std::string_view value, uint64_t maximum,
                       uint64_t& output) noexcept {
    if (value.size() < 3 || value[0] != '0' ||
        (value[1] != 'x' && value[1] != 'X'))
        return false;
    value.remove_prefix(2);
    if (value.empty() || value.size() > 16) return false;
    uint64_t parsed = 0;
    for (char c : value) {
        const int digit = hexDigit(c);
        if (digit < 0 || parsed > (maximum - static_cast<unsigned>(digit)) / 16)
            return false;
        parsed = parsed * 16 + static_cast<unsigned>(digit);
    }
    output = parsed;
    return true;
}

bool parseHexI64(std::string_view value, int64_t& output) noexcept {
    const bool negative = !value.empty() && value.front() == '-';
    if (negative) value.remove_prefix(1);
    const uint64_t maximum = negative
        ? uint64_t{1} << 63
        : static_cast<uint64_t>((std::numeric_limits<int64_t>::max)());
    uint64_t magnitude = 0;
    if (!parseHexMagnitude(value, maximum, magnitude)) return false;
    if (!negative) {
        output = static_cast<int64_t>(magnitude);
    } else if (magnitude == (uint64_t{1} << 63)) {
        output = (std::numeric_limits<int64_t>::min)();
    } else {
        output = -static_cast<int64_t>(magnitude);
    }
    return true;
}

bool integerType(MemoryValueType type, size_t& width,
                 bool& isSigned) noexcept {
    switch (type) {
        case MemoryValueType::UInt8:  width = 1; isSigned = false; return true;
        case MemoryValueType::Int8:   width = 1; isSigned = true; return true;
        case MemoryValueType::UInt16: width = 2; isSigned = false; return true;
        case MemoryValueType::Int16:  width = 2; isSigned = true; return true;
        case MemoryValueType::UInt32: width = 4; isSigned = false; return true;
        case MemoryValueType::Int32:  width = 4; isSigned = true; return true;
        case MemoryValueType::UInt64: width = 8; isSigned = false; return true;
        case MemoryValueType::Int64:  width = 8; isSigned = true; return true;
        default: return false;
    }
}

uint64_t widthMask(size_t width) noexcept {
    return width == 8 ? UINT64_MAX : (uint64_t{1} << (width * 8)) - 1;
}

int64_t signedValue(uint64_t raw, size_t width) noexcept {
    raw &= widthMask(width);
    const uint64_t sign = uint64_t{1} << (width * 8 - 1);
    if (!(raw & sign)) return static_cast<int64_t>(raw);
    const uint64_t magnitude = ((~raw) & widthMask(width)) + 1;
    if (width == 8 && magnitude == sign)
        return (std::numeric_limits<int64_t>::min)();
    return -static_cast<int64_t>(magnitude);
}

bool finiteFloatValue(MemoryValueType type,
                      std::span<const uint8_t> bytes) noexcept {
    if (type == MemoryValueType::Float32 && bytes.size() >= sizeof(float)) {
        float value = 0;
        std::memcpy(&value, bytes.data(), sizeof(value));
        return std::isfinite(value);
    }
    if (type == MemoryValueType::Float64 && bytes.size() >= sizeof(double)) {
        double value = 0;
        std::memcpy(&value, bytes.data(), sizeof(value));
        return std::isfinite(value);
    }
    return false;
}

bool desiredValue(const MemoryTableRecord& record, MemoryScanValue& parsed,
                  std::string* error) {
    if (record.desiredValueText.empty()) {
        if (record.freezeMode == MemoryFreezeMode::None) return true;
        setError(error, "active freeze mode requires a desired value");
        return false;
    }
    MemoryValueParseOptions options;
    options.hexadecimal = record.displayHex;
    options.nullTerminateText = record.nullTerminateText;
    std::string parseError;
    if (!ParseMemoryScanValue(record.type, record.desiredValueText,
                              options, parsed, &parseError) ||
        parsed.bytes.empty()) {
        setError(error, parseError.empty() ? "invalid desired value" : parseError);
        return false;
    }
    if (!parsed.mask.empty() &&
        std::find(parsed.mask.begin(), parsed.mask.end(), uint8_t{0}) !=
            parsed.mask.end()) {
        setError(error, "a write value cannot contain wildcard bytes");
        return false;
    }
    if ((record.freezeMode == MemoryFreezeMode::Minimum ||
         record.freezeMode == MemoryFreezeMode::Maximum) &&
        !MemoryValueTypeIsNumeric(record.type)) {
        setError(error, "minimum/maximum freeze requires a numeric type");
        return false;
    }
    if ((record.freezeMode == MemoryFreezeMode::Minimum ||
         record.freezeMode == MemoryFreezeMode::Maximum) &&
        MemoryValueTypeIsFloat(record.type) &&
        !finiteFloatValue(record.type, parsed.bytes)) {
        setError(error, "minimum/maximum freeze requires a finite limit");
        return false;
    }
    return true;
}

bool validateRecord(const MemoryTableRecord& record, std::string* error) {
    if (!noNul(record.description, kMemoryTableMaxDescriptionBytes)) {
        setError(error, "record description is too long or contains NUL");
        return false;
    }
    if (!noNul(record.group, kMemoryTableMaxGroupBytes)) {
        setError(error, "record group is too long or contains NUL");
        return false;
    }
    if (!knownValueType(record.type) || !knownFreezeMode(record.freezeMode)) {
        setError(error, "record contains an unknown value or freeze type");
        return false;
    }
    if (record.nullTerminateText && record.type != MemoryValueType::Utf8 &&
        record.type != MemoryValueType::Utf16Le) {
        setError(error, "NUL termination is only valid for text records");
        return false;
    }
    if (!noNul(record.desiredValueText, kMemoryTableMaxDesiredValueBytes)) {
        setError(error, "desired value is too long or contains NUL");
        return false;
    }
    if (record.address.pointerOffsets.size() > kMemoryTableMaxPointerDepth) {
        setError(error, "pointer chain exceeds the depth limit");
        return false;
    }
    if (record.address.kind == MemoryTableBaseKind::ModuleRelative) {
        if (!pathTextValid(record.address.moduleName,
                           kMemoryTableMaxModuleNameBytes) ||
            !pathTextValid(record.address.modulePath,
                           kMemoryTableMaxModulePathBytes) ||
            (record.address.moduleName.empty() && record.address.modulePath.empty())) {
            setError(error, "module-relative record needs a bounded module identity");
            return false;
        }
    } else if (record.address.kind != MemoryTableBaseKind::Absolute) {
        setError(error, "record has an unknown address kind");
        return false;
    }
    MemoryScanValue parsed;
    return desiredValue(record, parsed, error);
}

const json::Value* required(const json::Value& object, std::string_view key,
                            json::Type type, std::string* error) {
    const json::Value* value = object.find(std::string(key));
    if (!value || value->type != type) {
        setError(error, "missing or malformed field: " + std::string(key));
        return nullptr;
    }
    return value;
}

bool optionalBool(const json::Value& object, std::string_view key,
                  std::string* error) {
    const json::Value* value = object.find(std::string(key));
    if (value && value->type != json::Type::Bool) {
        setError(error, "malformed boolean field: " + std::string(key));
        return false;
    }
    return true;
}

json::Value addressToJson(const MemoryTableAddress& address) {
    json::Value object = json::Value::Obj();
    if (address.kind == MemoryTableBaseKind::Absolute) {
        object.set("kind", json::Value::Str("absolute"));
        object.set("absolute", json::Value::Str(hexU64(address.absoluteAddress)));
    } else {
        object.set("kind", json::Value::Str("module_relative"));
        object.set("module_name", json::Value::Str(address.moduleName));
        object.set("module_path", json::Value::Str(address.modulePath));
        object.set("offset", json::Value::Str(hexU64(address.moduleOffset)));
    }
    json::Value offsets = json::Value::Arr();
    for (const int64_t offset : address.pointerOffsets)
        offsets.push(json::Value::Str(hexI64(offset)));
    object.set("pointer_offsets", std::move(offsets));
    return object;
}

bool addressFromJson(const json::Value& object, MemoryTableAddress& output,
                     std::string* error) {
    if (!object.isObj()) {
        setError(error, "record address must be an object");
        return false;
    }
    const json::Value* kind = required(object, "kind", json::Type::Str, error);
    const json::Value* offsets =
        required(object, "pointer_offsets", json::Type::Arr, error);
    if (!kind || !offsets) return false;
    if (offsets->arr.size() > kMemoryTableMaxPointerDepth) {
        setError(error, "pointer chain exceeds the depth limit");
        return false;
    }

    MemoryTableAddress parsed;
    if (kind->str == "absolute") {
        parsed.kind = MemoryTableBaseKind::Absolute;
        const json::Value* absolute =
            required(object, "absolute", json::Type::Str, error);
        if (!absolute ||
            !parseHexMagnitude(absolute->str, UINT64_MAX,
                               parsed.absoluteAddress)) {
            setError(error, "absolute address must be a 64-bit hex string");
            return false;
        }
    } else if (kind->str == "module_relative") {
        parsed.kind = MemoryTableBaseKind::ModuleRelative;
        const json::Value* name =
            required(object, "module_name", json::Type::Str, error);
        const json::Value* path =
            required(object, "module_path", json::Type::Str, error);
        const json::Value* offset =
            required(object, "offset", json::Type::Str, error);
        if (!name || !path || !offset) return false;
        parsed.moduleName = name->str;
        parsed.modulePath = path->str;
        if (!parseHexMagnitude(offset->str, UINT64_MAX, parsed.moduleOffset)) {
            setError(error, "module offset must be a 64-bit hex string");
            return false;
        }
    } else {
        setError(error, "unknown address kind");
        return false;
    }

    parsed.pointerOffsets.reserve(offsets->arr.size());
    for (const json::Value& value : offsets->arr) {
        int64_t offset = 0;
        if (!value.isStr() || !parseHexI64(value.str, offset)) {
            setError(error, "pointer offsets must be signed 64-bit hex strings");
            return false;
        }
        parsed.pointerOffsets.push_back(offset);
    }
    output = std::move(parsed);
    return true;
}

} // namespace

MemoryTableResolveResult ResolveMemoryTableAddress(
    const MemoryTableAddress& spec,
    std::span<const MemoryTableModuleView> modules,
    const MemoryTableReader& reader,
    uint8_t pointerWidth,
    bool requireCanonical) {
    MemoryTableResolveResult result;
    if (pointerWidth != 4 && pointerWidth != 8) {
        result.status = MemoryTableResolveStatus::InvalidPointerWidth;
        return result;
    }
    if (spec.pointerOffsets.size() > kMemoryTableMaxPointerDepth) {
        result.status = MemoryTableResolveStatus::PointerDepthLimit;
        return result;
    }

    uint64_t cursor = 0;
    if (spec.kind == MemoryTableBaseKind::Absolute) {
        cursor = spec.absoluteAddress;
    } else if (spec.kind == MemoryTableBaseKind::ModuleRelative) {
        if (spec.moduleName.empty() && spec.modulePath.empty()) {
            result.status = MemoryTableResolveStatus::InvalidAddress;
            return result;
        }

        std::vector<size_t> matches;
        bool matchedByPath = false;
        if (!spec.modulePath.empty()) {
            const std::string wantedPath = normalizePath(spec.modulePath);
            for (size_t i = 0; i < modules.size(); ++i) {
                if (!modules[i].path.empty() &&
                    normalizePath(modules[i].path) == wantedPath)
                    matches.push_back(i);
            }
            matchedByPath = !matches.empty();
        }
        if (matches.empty()) {
            std::string wantedName = basenameKey(spec.moduleName);
            if (wantedName.empty()) wantedName = basenameKey(spec.modulePath);
            if (wantedName.empty()) {
                result.status = MemoryTableResolveStatus::ModuleNotFound;
                return result;
            }
            for (size_t i = 0; i < modules.size(); ++i) {
                const bool nameMatch = basenameKey(modules[i].name) == wantedName;
                const bool pathNameMatch = basenameKey(modules[i].path) == wantedName;
                if (nameMatch || pathNameMatch) matches.push_back(i);
            }
        }
        if (matches.empty()) {
            result.status = MemoryTableResolveStatus::ModuleNotFound;
            return result;
        }

        // Never choose a same-name (or duplicate-path) module by enumeration
        // order. Even duplicate projections are rejected: a caller can dedupe
        // its stable module snapshot before granting write authority.
        if (matches.size() != 1) {
            result.status = MemoryTableResolveStatus::AmbiguousModule;
            return result;
        }
        const size_t selected = matches.front();
        if (modules[selected].size &&
            (spec.moduleOffset >= modules[selected].size ||
             (!spec.pointerOffsets.empty() &&
              modules[selected].size - spec.moduleOffset < pointerWidth))) {
            result.status = MemoryTableResolveStatus::ModuleOffsetOutsideImage;
            return result;
        }
        if (!addUnsigned(modules[selected].base, spec.moduleOffset,
                         pointerWidth, cursor)) {
            result.status = MemoryTableResolveStatus::ArithmeticOverflow;
            return result;
        }
        result.moduleBase = modules[selected].base;
        result.moduleIndex = selected;
        result.moduleMatchedByPath = matchedByPath;
    } else {
        result.status = MemoryTableResolveStatus::InvalidAddress;
        return result;
    }

    // A WOW64 address is always 32-bit, even when the caller opts out of the
    // x64 canonical-address check for an unusual native target.
    if ((pointerWidth == 4 && cursor > UINT32_MAX) ||
        (requireCanonical && !canonicalAddress(cursor, pointerWidth))) {
        result.status = MemoryTableResolveStatus::NonCanonicalAddress;
        result.address = cursor;
        return result;
    }
    result.address = cursor;
    result.addresses.push_back(cursor);

    for (const int64_t offset : spec.pointerOffsets) {
        MemoryTableResolveStatus failure = MemoryTableResolveStatus::ReadFailure;
        if (!readablePointerSpan(cursor, pointerWidth, requireCanonical, failure)) {
            result.status = failure;
            return result;
        }
        if (!reader) {
            result.status = MemoryTableResolveStatus::ReadFailure;
            return result;
        }
        uint8_t bytes[8]{};
        size_t read = 0;
        try {
            read = reader(cursor, bytes, pointerWidth);
        } catch (...) {
            result.status = MemoryTableResolveStatus::ReaderException;
            return result;
        }
        if (read != pointerWidth) {
            result.status = MemoryTableResolveStatus::ReadFailure;
            return result;
        }
        const uint64_t pointer = readLittleEndian(bytes, pointerWidth);
        if (!pointer) {
            result.status = MemoryTableResolveStatus::NullPointer;
            return result;
        }
        if (requireCanonical && !canonicalAddress(pointer, pointerWidth)) {
            result.status = MemoryTableResolveStatus::NonCanonicalPointer;
            return result;
        }
        uint64_t next = 0;
        if (!addSigned(pointer, offset, pointerWidth, next)) {
            result.status = MemoryTableResolveStatus::ArithmeticOverflow;
            return result;
        }
        if (requireCanonical && !canonicalAddress(next, pointerWidth)) {
            result.status = MemoryTableResolveStatus::NonCanonicalAddress;
            return result;
        }
        result.pointerValues.push_back(pointer);
        result.addresses.push_back(next);
        result.stepsResolved++;
        result.address = next;
        cursor = next;
    }
    result.status = MemoryTableResolveStatus::Resolved;
    return result;
}

MemoryFreezeDecision EvaluateMemoryFreezeValue(
    MemoryValueType type,
    MemoryFreezeMode mode,
    bool displayHex,
    std::string_view desiredText,
    std::span<const uint8_t> current,
    bool nullTerminateText) {
    MemoryFreezeDecision result;
    if (mode == MemoryFreezeMode::None) return result;
    if (!knownValueType(type) || !knownFreezeMode(mode)) {
        result.code = MemoryFreezeDecisionCode::UnsupportedMode;
        result.error = "unknown value or freeze type";
        return result;
    }

    MemoryTableRecord temporary;
    temporary.type = type;
    temporary.displayHex = displayHex;
    temporary.nullTerminateText = nullTerminateText;
    temporary.desiredValueText.assign(desiredText);
    temporary.freezeMode = mode;
    MemoryScanValue desired;
    if (!desiredValue(temporary, desired, &result.error)) {
        result.code = MemoryFreezeDecisionCode::InvalidDesiredValue;
        return result;
    }
    if (current.size() < desired.bytes.size()) {
        result.code = MemoryFreezeDecisionCode::InvalidCurrentValue;
        result.error = "current value is shorter than the configured type";
        return result;
    }

    bool write = false;
    if (mode == MemoryFreezeMode::Constant) {
        write = !std::equal(desired.bytes.begin(), desired.bytes.end(),
                            current.begin());
    } else if (mode == MemoryFreezeMode::Minimum ||
               mode == MemoryFreezeMode::Maximum) {
        const bool minimum = mode == MemoryFreezeMode::Minimum;
        if (type == MemoryValueType::Float32) {
            float now = 0, limit = 0;
            std::memcpy(&now, current.data(), sizeof(now));
            std::memcpy(&limit, desired.bytes.data(), sizeof(limit));
            write = std::isnan(now) || (minimum ? now < limit : now > limit);
        } else if (type == MemoryValueType::Float64) {
            double now = 0, limit = 0;
            std::memcpy(&now, current.data(), sizeof(now));
            std::memcpy(&limit, desired.bytes.data(), sizeof(limit));
            write = std::isnan(now) || (minimum ? now < limit : now > limit);
        } else {
            size_t width = 0;
            bool isSigned = false;
            if (!integerType(type, width, isSigned)) {
                result.code = MemoryFreezeDecisionCode::UnsupportedMode;
                result.error = "minimum/maximum freeze requires a numeric type";
                return result;
            }
            const uint64_t nowBits = readLittleEndian(current.data(), width);
            const uint64_t limitBits =
                readLittleEndian(desired.bytes.data(), width);
            if (isSigned) {
                const int64_t now = signedValue(nowBits, width);
                const int64_t limit = signedValue(limitBits, width);
                write = minimum ? now < limit : now > limit;
            } else {
                write = minimum ? nowBits < limitBits : nowBits > limitBits;
            }
        }
    } else {
        result.code = MemoryFreezeDecisionCode::UnsupportedMode;
        result.error = "unsupported freeze mode";
        return result;
    }

    if (write) {
        result.code = MemoryFreezeDecisionCode::WriteDesired;
        result.bytes = std::move(desired.bytes);
    } else {
        result.code = MemoryFreezeDecisionCode::AlreadySatisfied;
    }
    return result;
}

MemoryFreezeDecision EvaluateMemoryFreeze(
    const MemoryTableRecord& record,
    std::span<const uint8_t> currentValue) {
    if (!record.enabled || !record.freezeActive ||
        record.freezeMode == MemoryFreezeMode::None)
        return {};
    return EvaluateMemoryFreezeValue(record.type, record.freezeMode,
                                     record.displayHex,
                                     record.desiredValueText, currentValue,
                                     record.nullTerminateText);
}

bool SerializeMemoryTable(const MemoryTableDocument& document,
                          std::string& output,
                          std::string* error) {
    if (error) error->clear();
    try {
        if (document.version != kMemoryTableVersion) {
            setError(error, "unsupported memory-table version");
            return false;
        }
        if (!noNul(document.title, kMemoryTableMaxTitleBytes)) {
            setError(error, "table title is too long or contains NUL");
            return false;
        }
        if (document.records.size() > kMemoryTableMaxRecords) {
            setError(error, "table contains too many records");
            return false;
        }

        size_t dynamicJsonBytes = 0;
        if (!addEscapedStringBudget(dynamicJsonBytes, document.title)) {
            setError(error, "serialized table exceeds the byte limit");
            return false;
        }
        for (const MemoryTableRecord& record : document.records) {
            if (!addEscapedStringBudget(dynamicJsonBytes, record.description) ||
                !addEscapedStringBudget(dynamicJsonBytes, record.group) ||
                !addEscapedStringBudget(dynamicJsonBytes,
                                        record.desiredValueText) ||
                (record.address.kind == MemoryTableBaseKind::ModuleRelative &&
                 (!addEscapedStringBudget(dynamicJsonBytes,
                                         record.address.moduleName) ||
                  !addEscapedStringBudget(dynamicJsonBytes,
                                         record.address.modulePath)))) {
                setError(error, "serialized table exceeds the byte limit");
                return false;
            }
        }

        json::Value root = json::Value::Obj();
        root.set("format", json::Value::Str(std::string(kFormat)));
        root.set("version", json::Value::Int(kMemoryTableVersion));
        root.set("title", json::Value::Str(document.title));
        json::Value records = json::Value::Arr();
        for (const MemoryTableRecord& record : document.records) {
            std::string recordError;
            if (!validateRecord(record, &recordError)) {
                setError(error, "invalid record: " + recordError);
                return false;
            }
            json::Value item = json::Value::Obj();
            item.set("description", json::Value::Str(record.description));
            item.set("group", json::Value::Str(record.group));
            item.set("type", json::Value::Str(
                std::string(valueTypeName(record.type))));
            item.set("display_hex", json::Value::Bool(record.displayHex));
            item.set("null_terminate_text",
                     json::Value::Bool(record.nullTerminateText));
            item.set("address", addressToJson(record.address));
            item.set("desired_value", json::Value::Str(record.desiredValueText));
            item.set("freeze_mode", json::Value::Str(
                std::string(freezeModeName(record.freezeMode))));
            item.set("allow_protection_change",
                     json::Value::Bool(record.allowProtectionChange));
            // Never persist authority from a live session.
            item.set("enabled", json::Value::Bool(false));
            item.set("freeze_active", json::Value::Bool(false));
            records.push(std::move(item));
        }
        root.set("records", std::move(records));
        std::string encoded = json::Dump(root, true);
        if (encoded.size() > kMemoryTableMaxSerializedBytes) {
            setError(error, "serialized table exceeds the byte limit");
            return false;
        }
        output = std::move(encoded);
        setError(error, {});
        return true;
    } catch (const std::bad_alloc&) {
        setError(error, "memory-table serialization ran out of memory");
        return false;
    } catch (...) {
        setError(error, "memory-table serialization failed");
        return false;
    }
}

bool DeserializeMemoryTable(std::string_view input,
                            MemoryTableDocument& output,
                            std::string* error) {
    if (error) error->clear();
    try {
        if (input.empty() || input.size() > kMemoryTableMaxSerializedBytes ||
            input.find('\0') != std::string_view::npos) {
            setError(error, "memory-table JSON is empty, oversized, or contains NUL");
            return false;
        }
        json::JsonParseLimits limits;
        limits.maxDepth = 10;
        limits.maxNodes = 400'000;
        limits.maxStringBytes = kMemoryTableMaxSerializedBytes;
        limits.maxContainerEntries = kMemoryTableMaxRecords;
        // A valid decoded string can expand to six JSON source bytes per byte
        // when every character needs a \u00XX escape. Keep serialization and
        // deserialization bounds symmetric while retaining a hard token cap.
        limits.maxStringTokenBytes =
            kMemoryTableMaxDesiredValueBytes * 6 + 2;
        limits.maxNumberTokenBytes = 32;
        json::Value root;
        if (!json::Parse(std::string(input), root, limits) || !root.isObj()) {
            setError(error, "invalid memory-table JSON");
            return false;
        }
        const json::Value* format =
            required(root, "format", json::Type::Str, error);
        const json::Value* version =
            required(root, "version", json::Type::Num, error);
        const json::Value* title =
            required(root, "title", json::Type::Str, error);
        const json::Value* records =
            required(root, "records", json::Type::Arr, error);
        if (!format || !version || !title || !records) return false;
        if (format->str != kFormat) {
            setError(error, "not a DisasmStudio memory table");
            return false;
        }
        if (!std::isfinite(version->num) ||
            version->num != static_cast<double>(kMemoryTableVersion)) {
            setError(error, "unsupported memory-table version");
            return false;
        }
        if (!noNul(title->str, kMemoryTableMaxTitleBytes) ||
            records->arr.size() > kMemoryTableMaxRecords) {
            setError(error, "memory-table document exceeds a configured bound");
            return false;
        }

        MemoryTableDocument parsed;
        parsed.version = kMemoryTableVersion;
        parsed.title = title->str;
        parsed.records.reserve(records->arr.size());
        for (const json::Value& item : records->arr) {
            if (!item.isObj()) {
                setError(error, "memory-table record must be an object");
                return false;
            }
            const json::Value* description =
                required(item, "description", json::Type::Str, error);
            const json::Value* group =
                required(item, "group", json::Type::Str, error);
            const json::Value* type =
                required(item, "type", json::Type::Str, error);
            const json::Value* displayHex =
                required(item, "display_hex", json::Type::Bool, error);
            const json::Value* nullTerminate =
                item.find("null_terminate_text");
            const json::Value* address =
                required(item, "address", json::Type::Obj, error);
            const json::Value* desired =
                required(item, "desired_value", json::Type::Str, error);
            const json::Value* freeze =
                required(item, "freeze_mode", json::Type::Str, error);
            const json::Value* protection =
                required(item, "allow_protection_change", json::Type::Bool, error);
            if (!description || !group || !type || !displayHex ||
                (nullTerminate && nullTerminate->type != json::Type::Bool) || !address ||
                !desired || !freeze || !protection ||
                !optionalBool(item, "enabled", error) ||
                !optionalBool(item, "freeze_active", error))
                return false;

            MemoryTableRecord record;
            record.description = description->str;
            record.group = group->str;
            record.displayHex = displayHex->b;
            record.nullTerminateText = nullTerminate ? nullTerminate->b : false;
            record.desiredValueText = desired->str;
            record.allowProtectionChange = protection->b;
            if (!parseValueType(type->str, record.type) ||
                !parseFreezeMode(freeze->str, record.freezeMode) ||
                !addressFromJson(*address, record.address, error)) {
                if (error && error->empty())
                    *error = "record contains an unknown type or freeze mode";
                return false;
            }

            // Deliberately ignore any saved runtime state, including future or
            // legacy aliases left as unknown fields in this version.
            record.enabled = false;
            record.freezeActive = false;
            std::string recordError;
            if (!validateRecord(record, &recordError)) {
                setError(error, "invalid record: " + recordError);
                return false;
            }
            parsed.records.push_back(std::move(record));
        }
        output = std::move(parsed);
        setError(error, {});
        return true;
    } catch (const std::bad_alloc&) {
        setError(error, "memory-table parsing ran out of memory");
        return false;
    } catch (...) {
        setError(error, "memory-table parsing failed");
        return false;
    }
}

} // namespace ds
