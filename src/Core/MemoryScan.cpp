#include "MemoryScan.h"

#include <algorithm>
#include <bit>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <system_error>

namespace ds {
namespace {

void setError(std::string* error, const char* text) {
    if (error) *error = text ? text : "";
}

std::string_view trimAscii(std::string_view text) noexcept {
    auto space = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
               c == '\f' || c == '\v';
    };
    while (!text.empty() && space(static_cast<unsigned char>(text.front())))
        text.remove_prefix(1);
    while (!text.empty() && space(static_cast<unsigned char>(text.back())))
        text.remove_suffix(1);
    return text;
}

int hexDigit(unsigned char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool integerType(MemoryValueType type, size_t& width, bool& isSigned) noexcept {
    switch (type) {
        case MemoryValueType::UInt8:  width = 1; isSigned = false; return true;
        case MemoryValueType::Int8:   width = 1; isSigned = true;  return true;
        case MemoryValueType::UInt16: width = 2; isSigned = false; return true;
        case MemoryValueType::Int16:  width = 2; isSigned = true;  return true;
        case MemoryValueType::UInt32: width = 4; isSigned = false; return true;
        case MemoryValueType::Int32:  width = 4; isSigned = true;  return true;
        case MemoryValueType::UInt64: width = 8; isSigned = false; return true;
        case MemoryValueType::Int64:  width = 8; isSigned = true;  return true;
        default: return false;
    }
}

uint64_t widthMask(size_t width) noexcept {
    return width >= 8 ? UINT64_MAX : ((uint64_t{1} << (width * 8)) - 1);
}

uint64_t readLe(const uint8_t* bytes, size_t width) noexcept {
    uint64_t bits = 0;
    for (size_t i = 0; i < width; ++i)
        bits |= uint64_t{bytes[i]} << (i * 8);
    return bits;
}

void writeLe(uint64_t bits, size_t width, std::vector<uint8_t>& bytes) {
    bytes.resize(width);
    for (size_t i = 0; i < width; ++i)
        bytes[i] = static_cast<uint8_t>(bits >> (i * 8));
}

int64_t signedFromBits(uint64_t raw, size_t width) noexcept {
    raw &= widthMask(width);
    const unsigned bits = static_cast<unsigned>(width * 8);
    const uint64_t sign = uint64_t{1} << (bits - 1);
    if (!(raw & sign)) return static_cast<int64_t>(raw);
    const uint64_t magnitude = ((~raw) & widthMask(width)) + 1;
    if (bits == 64 && magnitude == sign)
        return (std::numeric_limits<int64_t>::min)();
    return -static_cast<int64_t>(magnitude);
}

uint64_t unsignedMaximum(size_t width) noexcept {
    return widthMask(width);
}

int64_t signedMinimum(size_t width) noexcept {
    if (width >= 8) return (std::numeric_limits<int64_t>::min)();
    return -(int64_t{1} << (width * 8 - 1));
}

int64_t signedMaximum(size_t width) noexcept {
    if (width >= 8) return (std::numeric_limits<int64_t>::max)();
    return (int64_t{1} << (width * 8 - 1)) - 1;
}

bool parseUnsigned(std::string_view text, int base, uint64_t maximum,
                   uint64_t& result) noexcept {
    text = trimAscii(text);
    if (text.empty() || text.front() == '-') return false;
    if (text.front() == '+') text.remove_prefix(1);
    if (base == 16 && text.size() >= 2 && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X'))
        text.remove_prefix(2);
    if (text.empty()) return false;
    uint64_t candidate = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(),
                                        candidate, base);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        candidate > maximum)
        return false;
    result = candidate;
    return true;
}

bool parseSignedDecimal(std::string_view text, size_t width,
                        int64_t& result) noexcept {
    text = trimAscii(text);
    if (text.empty()) return false;
    if (text.front() == '+') text.remove_prefix(1);
    if (text.empty()) return false;
    int64_t candidate = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(),
                                        candidate, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        candidate < signedMinimum(width) || candidate > signedMaximum(width))
        return false;
    result = candidate;
    return true;
}

bool startsWithBitsPrefix(std::string_view text) noexcept {
    return text.size() >= 5 && text[0] == 'b' && text[1] == 'i' &&
           text[2] == 't' && text[3] == 's' && text[4] == ':';
}

bool decodeUtf8(std::string_view text, std::vector<uint32_t>& codepoints) {
    codepoints.clear();
    for (size_t i = 0; i < text.size();) {
        const uint8_t first = static_cast<uint8_t>(text[i]);
        uint32_t cp = 0;
        size_t continuation = 0;
        if (first <= 0x7F) {
            cp = first;
        } else if (first >= 0xC2 && first <= 0xDF) {
            cp = first & 0x1F;
            continuation = 1;
        } else if (first >= 0xE0 && first <= 0xEF) {
            cp = first & 0x0F;
            continuation = 2;
        } else if (first >= 0xF0 && first <= 0xF4) {
            cp = first & 0x07;
            continuation = 3;
        } else {
            return false;
        }
        if (continuation > text.size() - i - 1) return false;
        for (size_t j = 1; j <= continuation; ++j) {
            const uint8_t c = static_cast<uint8_t>(text[i + j]);
            if ((c & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3F);
        }
        if ((continuation == 2 && cp < 0x800) ||
            (continuation == 3 && cp < 0x10000) ||
            cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return false;
        codepoints.push_back(cp);
        i += continuation + 1;
    }
    return true;
}

void appendUtf8(uint32_t cp, std::string& out) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string fixedHex(uint64_t bits, size_t width) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out(2 + width * 2, '0');
    out[0] = '0';
    out[1] = 'x';
    for (size_t i = 0; i < width * 2; ++i) {
        const size_t shift = (width * 2 - i - 1) * 4;
        out[2 + i] = digits[(bits >> shift) & 0xF];
    }
    return out;
}

bool modeNeedsValue(MemoryScanMode mode) noexcept {
    switch (mode) {
        case MemoryScanMode::Exact:
        case MemoryScanMode::NotEqual:
        case MemoryScanMode::GreaterThanValue:
        case MemoryScanMode::LessThanValue:
        case MemoryScanMode::Between:
        case MemoryScanMode::IncreasedBy:
        case MemoryScanMode::DecreasedBy:
            return true;
        default:
            return false;
    }
}

bool modeNeedsPrevious(MemoryScanMode mode) noexcept {
    switch (mode) {
        case MemoryScanMode::Changed:
        case MemoryScanMode::Unchanged:
        case MemoryScanMode::Increased:
        case MemoryScanMode::Decreased:
        case MemoryScanMode::IncreasedBy:
        case MemoryScanMode::DecreasedBy:
            return true;
        default:
            return false;
    }
}

bool initialModeUsesBaseline(MemoryScanMode mode) noexcept {
    return modeNeedsPrevious(mode) || mode == MemoryScanMode::UnknownInitial;
}

bool modeNeedsNumeric(MemoryScanMode mode) noexcept {
    switch (mode) {
        case MemoryScanMode::GreaterThanValue:
        case MemoryScanMode::LessThanValue:
        case MemoryScanMode::Between:
        case MemoryScanMode::Increased:
        case MemoryScanMode::Decreased:
        case MemoryScanMode::IncreasedBy:
        case MemoryScanMode::DecreasedBy:
            return true;
        default:
            return false;
    }
}

bool sameValue(const MemoryScanValue& a, const MemoryScanValue& b) noexcept {
    return a.type == b.type && a.bytes == b.bytes && a.mask == b.mask &&
           a.nullTerminated == b.nullTerminated;
}

bool sameConfig(const MemoryScanConfig& a, const MemoryScanConfig& b) noexcept {
    return a.type == b.type && a.mode == b.mode && a.alignment == b.alignment &&
           a.elementSize == b.elementSize &&
           a.tolerance.enabled == b.tolerance.enabled &&
           a.tolerance.absolute == b.tolerance.absolute &&
           a.tolerance.relative == b.tolerance.relative &&
           sameValue(a.value, b.value) && sameValue(a.secondValue, b.secondValue);
}

struct Numeric {
    enum class Kind : uint8_t { Unsigned, Signed, Floating } kind = Kind::Unsigned;
    uint64_t u = 0;
    int64_t s = 0;
    long double f = 0;
    size_t width = 0;
};

bool decodeNumeric(MemoryValueType type, const uint8_t* bytes,
                   size_t size, Numeric& out) noexcept {
    const size_t width = MemoryValueTypeFixedSize(type);
    if (!bytes || !width || size < width || !MemoryValueTypeIsNumeric(type))
        return false;
    out = {};
    out.width = width;
    if (type == MemoryValueType::Float32) {
        const uint32_t raw = static_cast<uint32_t>(readLe(bytes, 4));
        float value = 0;
        std::memcpy(&value, &raw, sizeof(value));
        out.kind = Numeric::Kind::Floating;
        out.f = static_cast<long double>(value);
        return true;
    }
    if (type == MemoryValueType::Float64) {
        const uint64_t raw = readLe(bytes, 8);
        double value = 0;
        std::memcpy(&value, &raw, sizeof(value));
        out.kind = Numeric::Kind::Floating;
        out.f = static_cast<long double>(value);
        return true;
    }
    bool isSigned = false;
    size_t integerWidth = 0;
    if (!integerType(type, integerWidth, isSigned)) return false;
    const uint64_t raw = readLe(bytes, integerWidth);
    if (isSigned) {
        out.kind = Numeric::Kind::Signed;
        out.s = signedFromBits(raw, integerWidth);
    } else {
        out.kind = Numeric::Kind::Unsigned;
        out.u = raw & widthMask(integerWidth);
    }
    return true;
}

bool almostEqual(long double a, long double b,
                 const MemoryFloatTolerance& tolerance) noexcept {
    if (a == b) return true;
    if (!std::isfinite(a) || !std::isfinite(b)) return false;
    const long double difference = std::fabs(a - b);
    const long double scale = (std::max)(std::fabs(a), std::fabs(b));
    const long double allowed = (std::max)(
        static_cast<long double>(tolerance.absolute),
        static_cast<long double>(tolerance.relative) * scale);
    return difference <= allowed;
}

bool equalNumeric(const Numeric& a, const Numeric& b,
                  const MemoryFloatTolerance& tolerance) noexcept {
    if (a.kind != b.kind) return false;
    switch (a.kind) {
        case Numeric::Kind::Unsigned: return a.u == b.u;
        case Numeric::Kind::Signed:   return a.s == b.s;
        case Numeric::Kind::Floating:
            return tolerance.enabled ? almostEqual(a.f, b.f, tolerance)
                                     : a.f == b.f;
    }
    return false;
}

bool lessNumeric(const Numeric& a, const Numeric& b,
                 const MemoryFloatTolerance& tolerance) noexcept {
    if (a.kind != b.kind) return false;
    switch (a.kind) {
        case Numeric::Kind::Unsigned: return a.u < b.u;
        case Numeric::Kind::Signed:   return a.s < b.s;
        case Numeric::Kind::Floating:
            return a.f < b.f &&
                   (!tolerance.enabled || !almostEqual(a.f, b.f, tolerance));
    }
    return false;
}

bool greaterNumeric(const Numeric& a, const Numeric& b,
                    const MemoryFloatTolerance& tolerance) noexcept {
    return lessNumeric(b, a, tolerance);
}

bool maskedEqual(const uint8_t* current, const MemoryScanValue& value,
                 size_t width) noexcept {
    for (size_t i = 0; i < width; ++i) {
        const uint8_t mask = value.mask.empty() ? 0xFF : value.mask[i];
        if ((current[i] & mask) != (value.bytes[i] & mask)) return false;
    }
    return true;
}

bool rawEqual(const uint8_t* a, const uint8_t* b, size_t width) noexcept {
    return std::memcmp(a, b, width) == 0;
}

bool predicateUnchecked(const MemoryScanConfig& config,
                        const uint8_t* current, const uint8_t* previous,
                        size_t width) noexcept {
    if (config.mode == MemoryScanMode::UnknownInitial) return true;

    if (config.mode == MemoryScanMode::Exact ||
        config.mode == MemoryScanMode::NotEqual) {
        bool equal = false;
        if (MemoryValueTypeIsFloat(config.type) && config.tolerance.enabled) {
            Numeric cur, needle;
            equal = decodeNumeric(config.type, current, width, cur) &&
                    decodeNumeric(config.type, config.value.bytes.data(),
                                  config.value.bytes.size(), needle) &&
                    equalNumeric(cur, needle, config.tolerance);
        } else {
            equal = maskedEqual(current, config.value, width);
        }
        return config.mode == MemoryScanMode::Exact ? equal : !equal;
    }

    if (config.mode == MemoryScanMode::Changed ||
        config.mode == MemoryScanMode::Unchanged) {
        bool equal = false;
        if (MemoryValueTypeIsFloat(config.type) && config.tolerance.enabled) {
            Numeric cur, prev;
            equal = decodeNumeric(config.type, current, width, cur) &&
                    decodeNumeric(config.type, previous, width, prev) &&
                    equalNumeric(cur, prev, config.tolerance);
        } else {
            equal = rawEqual(current, previous, width);
        }
        return config.mode == MemoryScanMode::Unchanged ? equal : !equal;
    }

    Numeric cur, reference;
    if (!decodeNumeric(config.type, current, width, cur)) return false;
    if (config.mode == MemoryScanMode::GreaterThanValue ||
        config.mode == MemoryScanMode::LessThanValue ||
        config.mode == MemoryScanMode::Between) {
        if (!decodeNumeric(config.type, config.value.bytes.data(),
                           config.value.bytes.size(), reference)) return false;
        if (config.mode == MemoryScanMode::GreaterThanValue)
            return greaterNumeric(cur, reference, config.tolerance);
        if (config.mode == MemoryScanMode::LessThanValue)
            return lessNumeric(cur, reference, config.tolerance);
        Numeric upper;
        if (!decodeNumeric(config.type, config.secondValue.bytes.data(),
                           config.secondValue.bytes.size(), upper)) return false;
        const bool atOrAbove = greaterNumeric(cur, reference, config.tolerance) ||
                               equalNumeric(cur, reference, config.tolerance);
        const bool atOrBelow = lessNumeric(cur, upper, config.tolerance) ||
                               equalNumeric(cur, upper, config.tolerance);
        return atOrAbove && atOrBelow;
    }

    if (!previous || !decodeNumeric(config.type, previous, width, reference))
        return false;
    if (config.mode == MemoryScanMode::Increased)
        return greaterNumeric(cur, reference, config.tolerance);
    if (config.mode == MemoryScanMode::Decreased)
        return lessNumeric(cur, reference, config.tolerance);

    Numeric delta;
    if (!decodeNumeric(config.type, config.value.bytes.data(),
                       config.value.bytes.size(), delta) || delta.kind != cur.kind)
        return false;
    const bool increase = config.mode == MemoryScanMode::IncreasedBy;
    switch (cur.kind) {
        case Numeric::Kind::Unsigned:
            if (increase) {
                if (reference.u > unsignedMaximum(cur.width) - delta.u) return false;
                return cur.u == reference.u + delta.u;
            }
            if (reference.u < delta.u) return false;
            return cur.u == reference.u - delta.u;
        case Numeric::Kind::Signed:
            if (delta.s < 0) return false;
            if (increase) {
                if (reference.s > signedMaximum(cur.width) - delta.s) return false;
                return cur.s == reference.s + delta.s;
            }
            if (reference.s < signedMinimum(cur.width) + delta.s) return false;
            return cur.s == reference.s - delta.s;
        case Numeric::Kind::Floating: {
            if (!std::isfinite(cur.f) || !std::isfinite(reference.f) ||
                !std::isfinite(delta.f) || delta.f < 0)
                return false;
            const long double expected = increase ? reference.f + delta.f
                                                  : reference.f - delta.f;
            return std::isfinite(expected) &&
                   (config.tolerance.enabled
                        ? almostEqual(cur.f, expected, config.tolerance)
                        : cur.f == expected);
        }
    }
    return false;
}

bool finiteNeedle(const MemoryScanValue& value) noexcept {
    Numeric decoded;
    return decodeNumeric(value.type, value.bytes.data(), value.bytes.size(), decoded) &&
           (decoded.kind != Numeric::Kind::Floating || std::isfinite(decoded.f));
}

bool nonNegativeNeedle(const MemoryScanValue& value) noexcept {
    Numeric decoded;
    if (!decodeNumeric(value.type, value.bytes.data(), value.bytes.size(), decoded))
        return false;
    switch (decoded.kind) {
        case Numeric::Kind::Unsigned: return true;
        case Numeric::Kind::Signed: return decoded.s >= 0;
        case Numeric::Kind::Floating:
            return std::isfinite(decoded.f) && decoded.f >= 0;
    }
    return false;
}

} // namespace

bool MemoryValueTypeIsNumeric(MemoryValueType type) noexcept {
    return type <= MemoryValueType::Float64;
}

bool MemoryValueTypeIsFloat(MemoryValueType type) noexcept {
    return type == MemoryValueType::Float32 || type == MemoryValueType::Float64;
}

size_t MemoryValueTypeFixedSize(MemoryValueType type) noexcept {
    switch (type) {
        case MemoryValueType::UInt8:
        case MemoryValueType::Int8: return 1;
        case MemoryValueType::UInt16:
        case MemoryValueType::Int16: return 2;
        case MemoryValueType::UInt32:
        case MemoryValueType::Int32:
        case MemoryValueType::Float32: return 4;
        case MemoryValueType::UInt64:
        case MemoryValueType::Int64:
        case MemoryValueType::Float64: return 8;
        default: return 0;
    }
}

bool MemoryScanValue::valid() const noexcept {
    if (bytes.empty()) return false;
    const size_t fixed = MemoryValueTypeFixedSize(type);
    if (fixed && bytes.size() != fixed) return false;
    if (!mask.empty()) {
        if (type != MemoryValueType::ByteArray || mask.size() != bytes.size())
            return false;
        for (uint8_t byte : mask)
            if (byte != 0x00 && byte != 0xFF) return false;
    }
    if (nullTerminated) {
        if (type == MemoryValueType::Utf8) return bytes.back() == 0;
        if (type == MemoryValueType::Utf16Le)
            return bytes.size() >= 2 && bytes[bytes.size() - 2] == 0 &&
                   bytes.back() == 0;
        return false;
    }
    return true;
}

bool ParseMemoryScanValue(MemoryValueType type, std::string_view text,
                          const MemoryValueParseOptions& options,
                          MemoryScanValue& out, std::string* error) {
    setError(error, "");
    MemoryScanValue parsed;
    parsed.type = type;
    try {
        size_t integerWidth = 0;
        bool isSigned = false;
        if (integerType(type, integerWidth, isSigned)) {
            uint64_t bits = 0;
            if (options.hexadecimal) {
                if (!parseUnsigned(text, 16, unsignedMaximum(integerWidth), bits)) {
                    setError(error, "invalid or out-of-range hexadecimal integer");
                    return false;
                }
            } else if (isSigned) {
                int64_t value = 0;
                if (!parseSignedDecimal(text, integerWidth, value)) {
                    setError(error, "invalid or out-of-range signed integer");
                    return false;
                }
                bits = static_cast<uint64_t>(value) & widthMask(integerWidth);
            } else if (!parseUnsigned(text, 10, unsignedMaximum(integerWidth), bits)) {
                setError(error, "invalid or out-of-range unsigned integer");
                return false;
            }
            writeLe(bits, integerWidth, parsed.bytes);
        } else if (MemoryValueTypeIsFloat(type)) {
            const size_t width = MemoryValueTypeFixedSize(type);
            std::string_view numeric = trimAscii(text);
            bool rawBits = options.hexadecimal;
            if (startsWithBitsPrefix(numeric)) {
                rawBits = true;
                numeric.remove_prefix(5);
            }
            if (rawBits) {
                uint64_t bits = 0;
                if (!parseUnsigned(numeric, 16, unsignedMaximum(width), bits)) {
                    setError(error, "invalid or out-of-range floating-point bit pattern");
                    return false;
                }
                writeLe(bits, width, parsed.bytes);
            } else if (type == MemoryValueType::Float32) {
                if (!numeric.empty() && numeric.front() == '+') numeric.remove_prefix(1);
                float value = 0;
                const auto result = std::from_chars(
                    numeric.data(), numeric.data() + numeric.size(), value,
                    std::chars_format::general);
                if (numeric.empty() || result.ec != std::errc{} ||
                    result.ptr != numeric.data() + numeric.size() || !std::isfinite(value)) {
                    setError(error, "invalid, non-finite, or out-of-range float");
                    return false;
                }
                uint32_t bits = 0;
                std::memcpy(&bits, &value, sizeof(bits));
                writeLe(bits, 4, parsed.bytes);
            } else {
                if (!numeric.empty() && numeric.front() == '+') numeric.remove_prefix(1);
                double value = 0;
                const auto result = std::from_chars(
                    numeric.data(), numeric.data() + numeric.size(), value,
                    std::chars_format::general);
                if (numeric.empty() || result.ec != std::errc{} ||
                    result.ptr != numeric.data() + numeric.size() || !std::isfinite(value)) {
                    setError(error, "invalid, non-finite, or out-of-range double");
                    return false;
                }
                uint64_t bits = 0;
                std::memcpy(&bits, &value, sizeof(bits));
                writeLe(bits, 8, parsed.bytes);
            }
        } else if (type == MemoryValueType::ByteArray) {
            text = trimAscii(text);
            for (size_t i = 0; i < text.size();) {
                while (i < text.size() &&
                       (text[i] == ' ' || text[i] == '\t' || text[i] == '\r' ||
                        text[i] == '\n' || text[i] == ','))
                    ++i;
                if (i == text.size()) break;
                if (text[i] == '?') {
                    ++i;
                    if (i < text.size() && text[i] == '?') ++i;
                    parsed.bytes.push_back(0);
                    parsed.mask.push_back(0);
                    continue;
                }
                if (i + 1 < text.size() && text[i] == '0' &&
                    (text[i + 1] == 'x' || text[i + 1] == 'X'))
                    i += 2;
                if (i + 1 >= text.size()) {
                    setError(error, "byte array has an incomplete trailing byte");
                    return false;
                }
                const int high = hexDigit(static_cast<unsigned char>(text[i]));
                const int low = hexDigit(static_cast<unsigned char>(text[i + 1]));
                if (high < 0 || low < 0) {
                    setError(error, "byte array must contain hexadecimal byte pairs or ??");
                    return false;
                }
                parsed.bytes.push_back(static_cast<uint8_t>((high << 4) | low));
                parsed.mask.push_back(0xFF);
                i += 2;
            }
            if (parsed.bytes.empty()) {
                setError(error, "byte array is empty");
                return false;
            }
            if (std::all_of(parsed.mask.begin(), parsed.mask.end(),
                            [](uint8_t mask) { return mask == 0xFF; }))
                parsed.mask.clear();
        } else if (type == MemoryValueType::Utf8 ||
                   type == MemoryValueType::Utf16Le) {
            std::vector<uint32_t> codepoints;
            if (!decodeUtf8(text, codepoints)) {
                setError(error, "text is not well-formed UTF-8");
                return false;
            }
            if (type == MemoryValueType::Utf8) {
                parsed.bytes.assign(text.begin(), text.end());
                if (options.nullTerminateText) parsed.bytes.push_back(0);
            } else {
                parsed.bytes.reserve(codepoints.size() * 2 +
                                     (options.nullTerminateText ? 2 : 0));
                auto unit = [&](uint16_t value) {
                    parsed.bytes.push_back(static_cast<uint8_t>(value));
                    parsed.bytes.push_back(static_cast<uint8_t>(value >> 8));
                };
                for (uint32_t cp : codepoints) {
                    if (cp <= 0xFFFF) {
                        unit(static_cast<uint16_t>(cp));
                    } else {
                        cp -= 0x10000;
                        unit(static_cast<uint16_t>(0xD800 + (cp >> 10)));
                        unit(static_cast<uint16_t>(0xDC00 + (cp & 0x3FF)));
                    }
                }
                if (options.nullTerminateText) unit(0);
            }
            parsed.nullTerminated = options.nullTerminateText;
            if (parsed.bytes.empty()) {
                setError(error, "text value is empty");
                return false;
            }
        } else {
            setError(error, "unsupported memory value type");
            return false;
        }
    } catch (const std::bad_alloc&) {
        setError(error, "not enough memory to encode the value");
        return false;
    } catch (...) {
        setError(error, "value encoding failed");
        return false;
    }

    if (!parsed.valid()) {
        setError(error, "encoded value is structurally invalid");
        return false;
    }
    out = std::move(parsed);
    return true;
}

std::string FormatMemoryScanValue(const MemoryScanValue& value,
                                  const MemoryValueFormatOptions& options) {
    if (!value.valid()) return {};
    try {
        if (value.type == MemoryValueType::ByteArray) {
            std::string out;
            out.reserve(value.bytes.size() * 3);
            static constexpr char digits[] = "0123456789ABCDEF";
            for (size_t i = 0; i < value.bytes.size(); ++i) {
                if (i) out.push_back(' ');
                const uint8_t mask = value.mask.empty() ? 0xFF : value.mask[i];
                if (!mask) {
                    out += "??";
                } else {
                    out.push_back(digits[value.bytes[i] >> 4]);
                    out.push_back(digits[value.bytes[i] & 0xF]);
                }
            }
            return out;
        }
        if (value.type == MemoryValueType::Utf8) {
            size_t size = value.bytes.size();
            if (value.nullTerminated && size) --size;
            return std::string(reinterpret_cast<const char*>(value.bytes.data()), size);
        }
        if (value.type == MemoryValueType::Utf16Le) {
            size_t size = value.bytes.size();
            if (value.nullTerminated && size >= 2) size -= 2;
            if (size & 1) return {};
            std::string out;
            for (size_t i = 0; i < size; i += 2) {
                const uint16_t first = static_cast<uint16_t>(value.bytes[i]) |
                                       (static_cast<uint16_t>(value.bytes[i + 1]) << 8);
                uint32_t cp = first;
                if (first >= 0xD800 && first <= 0xDBFF) {
                    if (i + 3 >= size) return {};
                    const uint16_t second = static_cast<uint16_t>(value.bytes[i + 2]) |
                                            (static_cast<uint16_t>(value.bytes[i + 3]) << 8);
                    if (second < 0xDC00 || second > 0xDFFF) return {};
                    cp = 0x10000 + ((uint32_t(first - 0xD800) << 10) |
                                    uint32_t(second - 0xDC00));
                    i += 2;
                } else if (first >= 0xDC00 && first <= 0xDFFF) {
                    return {};
                }
                appendUtf8(cp, out);
            }
            return out;
        }

        const size_t width = MemoryValueTypeFixedSize(value.type);
        const uint64_t raw = readLe(value.bytes.data(), width);
        if (options.hexadecimal) return fixedHex(raw, width);

        size_t ignoredWidth = 0;
        bool isSigned = false;
        if (integerType(value.type, ignoredWidth, isSigned)) {
            char buffer[64]{};
            std::to_chars_result result;
            if (isSigned) {
                const int64_t number = signedFromBits(raw, width);
                result = std::to_chars(buffer, buffer + sizeof(buffer), number, 10);
            } else {
                result = std::to_chars(buffer, buffer + sizeof(buffer), raw, 10);
            }
            return result.ec == std::errc{} ? std::string(buffer, result.ptr) : std::string();
        }

        char buffer[128]{};
        if (value.type == MemoryValueType::Float32) {
            const uint32_t bits = static_cast<uint32_t>(raw);
            float number = 0;
            std::memcpy(&number, &bits, sizeof(number));
            if (!std::isfinite(number)) return std::string("bits:") + fixedHex(raw, width);
            const auto result = std::to_chars(
                buffer, buffer + sizeof(buffer), number, std::chars_format::general,
                std::numeric_limits<float>::max_digits10);
            return result.ec == std::errc{} ? std::string(buffer, result.ptr) : std::string();
        }
        const uint64_t bits = raw;
        double number = 0;
        std::memcpy(&number, &bits, sizeof(number));
        if (!std::isfinite(number)) return std::string("bits:") + fixedHex(raw, width);
        const auto result = std::to_chars(
            buffer, buffer + sizeof(buffer), number, std::chars_format::general,
            std::numeric_limits<double>::max_digits10);
        return result.ec == std::errc{} ? std::string(buffer, result.ptr) : std::string();
    } catch (...) {
        return {};
    }
}

size_t MemoryScanElementSize(const MemoryScanConfig& config) noexcept {
    const size_t fixed = MemoryValueTypeFixedSize(config.type);
    if (fixed) return fixed;
    if (config.elementSize) return config.elementSize;
    return config.value.size();
}

bool ValidateMemoryScanConfig(const MemoryScanConfig& config,
                              std::string* error) {
    setError(error, "");
    if (!config.alignment) {
        setError(error, "scan alignment must be at least one byte");
        return false;
    }
    const size_t width = MemoryScanElementSize(config);
    if (!width) {
        setError(error, "scan element size is zero");
        return false;
    }
    const size_t fixed = MemoryValueTypeFixedSize(config.type);
    if (fixed && config.elementSize && config.elementSize != fixed) {
        setError(error, "numeric element size does not match its value type");
        return false;
    }
    if (config.tolerance.enabled) {
        if (!MemoryValueTypeIsFloat(config.type)) {
            setError(error, "floating-point tolerance requires a float or double scan");
            return false;
        }
        if (!std::isfinite(config.tolerance.absolute) ||
            !std::isfinite(config.tolerance.relative) ||
            config.tolerance.absolute < 0 || config.tolerance.relative < 0) {
            setError(error, "floating-point tolerances must be finite and non-negative");
            return false;
        }
    }
    if (modeNeedsNumeric(config.mode) && !MemoryValueTypeIsNumeric(config.type)) {
        setError(error, "ordered and relative-delta scans require a numeric type");
        return false;
    }
    if (modeNeedsValue(config.mode)) {
        if (!config.value.valid() || config.value.type != config.type ||
            config.value.size() != width) {
            setError(error, "scan value does not match the selected type and width");
            return false;
        }
    }
    if (config.mode == MemoryScanMode::Between) {
        if (!config.secondValue.valid() || config.secondValue.type != config.type ||
            config.secondValue.size() != width) {
            setError(error, "between scan requires a matching upper bound");
            return false;
        }
        Numeric lower, upper;
        if (!decodeNumeric(config.type, config.value.bytes.data(), width, lower) ||
            !decodeNumeric(config.type, config.secondValue.bytes.data(), width, upper) ||
            !finiteNeedle(config.value) || !finiteNeedle(config.secondValue) ||
            greaterNumeric(lower, upper, {})) {
            setError(error, "between bounds must be finite and ordered low to high");
            return false;
        }
    } else if ((config.mode == MemoryScanMode::GreaterThanValue ||
                config.mode == MemoryScanMode::LessThanValue) &&
               !finiteNeedle(config.value)) {
        setError(error, "ordered scan value must be finite");
        return false;
    }
    if ((config.mode == MemoryScanMode::IncreasedBy ||
         config.mode == MemoryScanMode::DecreasedBy) &&
        !nonNegativeNeedle(config.value)) {
        setError(error, "relative scan delta must be finite and non-negative");
        return false;
    }
    return true;
}

bool MemoryScanPredicate(const MemoryScanConfig& config,
                         const uint8_t* current, size_t currentSize,
                         const uint8_t* previous, size_t previousSize) noexcept {
    const size_t width = MemoryScanElementSize(config);
    if (!width || !current || currentSize < width) return false;
    if (modeNeedsPrevious(config.mode) && (!previous || previousSize < width))
        return false;
    if (modeNeedsValue(config.mode) &&
        (!config.value.valid() || config.value.type != config.type ||
         config.value.size() != width))
        return false;
    if (config.mode == MemoryScanMode::Between &&
        (!config.secondValue.valid() || config.secondValue.type != config.type ||
         config.secondValue.size() != width))
        return false;
    return predicateUnchecked(config, current, previous, width);
}

bool MemoryScanChunk::candidateAtOffset(size_t offset) const noexcept {
    if (offset >= candidateSpan) return false;
    const size_t word = offset / 64;
    return word < candidateBitmap.size() &&
           ((candidateBitmap[word] >> (offset & 63)) & 1) != 0;
}

void MemoryScanSnapshot::clear() noexcept {
    shapeSet_ = false;
    type_ = MemoryValueType::UInt32;
    elementSize_ = 0;
    alignment_ = 1;
    initialConfig_ = {};
    chunks_.clear();
    candidateCount_ = 0;
    hasLastOwnedRange_ = false;
    lastOwnedEnd_ = 0;
}

bool MemoryScanSnapshot::appendInitialChunk(
    const MemoryScanConfig& config, uint64_t base,
    const uint8_t* sample, size_t sampleSize, size_t candidateSpan,
    std::string* error) {
    setError(error, "");
    if (!ValidateMemoryScanConfig(config, error)) return false;
    if (candidateSpan == kWholeSample) candidateSpan = sampleSize;
    if (!sample || !sampleSize || !candidateSpan || candidateSpan > sampleSize) {
        setError(error, "initial scan chunk has no valid owned byte span");
        return false;
    }
    if (sampleSize > UINT64_MAX - base || candidateSpan > UINT64_MAX - base) {
        setError(error, "initial scan chunk address range overflows");
        return false;
    }
    const size_t width = MemoryScanElementSize(config);
    if (shapeSet_) {
        if (type_ != config.type || elementSize_ != width ||
            alignment_ != config.alignment || !sameConfig(initialConfig_, config)) {
            setError(error, "initial chunks must use one consistent scan configuration");
            return false;
        }
    }
    if (hasLastOwnedRange_) {
        if (base < lastOwnedEnd_) {
            setError(error, "initial scan chunk ownership ranges overlap or are unsorted");
            return false;
        }
    }
    if (candidateSpan > (std::numeric_limits<size_t>::max)() - 63) {
        setError(error, "candidate bitmap is too large");
        return false;
    }

    MemoryScanChunk chunk;
    chunk.base = base;
    chunk.candidateSpan = candidateSpan;
    try {
        chunk.bytes.assign(sample, sample + sampleSize);
        chunk.candidateBitmap.assign((candidateSpan + 63) / 64, 0);
        const size_t lastComplete = sampleSize >= width ? sampleSize - width : 0;
        const bool anyComplete = sampleSize >= width;
        for (size_t offset = 0; offset < candidateSpan; ++offset) {
            if (!anyComplete || offset > lastComplete) break;
            const uint64_t address = base + offset;
            if (address % config.alignment) continue;
            const bool keep = initialModeUsesBaseline(config.mode) ||
                predicateUnchecked(config, sample + offset, nullptr, width);
            if (!keep) continue;
            chunk.candidateBitmap[offset / 64] |= uint64_t{1} << (offset & 63);
            ++chunk.candidateCount;
        }
    } catch (const std::bad_alloc&) {
        setError(error, "not enough memory to retain the initial scan chunk");
        return false;
    } catch (...) {
        setError(error, "initial scan chunk construction failed");
        return false;
    }
    if (chunk.candidateCount > UINT64_MAX - candidateCount_) {
        setError(error, "scan candidate count overflows");
        return false;
    }
    // Exact/value scans commonly have no hit in most pages. Their bytes can
    // never become candidates during a later refinement, so retaining those
    // pages would turn a sparse scan back into a whole-process snapshot.
    if (!chunk.candidateCount) {
        if (!shapeSet_) {
            shapeSet_ = true;
            type_ = config.type;
            elementSize_ = width;
            alignment_ = config.alignment;
            initialConfig_ = config;
        }
        hasLastOwnedRange_ = true;
        lastOwnedEnd_ = base + candidateSpan;
        return true;
    }
    try {
        chunks_.push_back(std::move(chunk));
    } catch (const std::bad_alloc&) {
        setError(error, "not enough memory to append the initial scan chunk");
        return false;
    } catch (...) {
        setError(error, "could not append the initial scan chunk");
        return false;
    }
    if (!shapeSet_) {
        shapeSet_ = true;
        type_ = config.type;
        elementSize_ = width;
        alignment_ = config.alignment;
        initialConfig_ = config;
    }
    candidateCount_ += chunks_.back().candidateCount;
    hasLastOwnedRange_ = true;
    lastOwnedEnd_ = base + candidateSpan;
    return true;
}

bool MemoryScanSnapshot::refineChunk(size_t index,
                                     const MemoryScanConfig& config,
                                     const uint8_t* current, size_t currentSize,
                                     std::string* error) {
    setError(error, "");
    if (!shapeSet_ || index >= chunks_.size()) {
        setError(error, "scan chunk index is out of range");
        return false;
    }
    if (!ValidateMemoryScanConfig(config, error)) return false;
    const size_t width = MemoryScanElementSize(config);
    if (config.type != type_ || width != elementSize_ ||
        config.alignment != alignment_) {
        setError(error, "refinement cannot change value type, width, or alignment");
        return false;
    }
    if (currentSize && !current) {
        setError(error, "refinement bytes are missing");
        return false;
    }

    const MemoryScanChunk& prior = chunks_[index];
    MemoryScanChunk refined;
    refined.base = prior.base;
    refined.candidateSpan = prior.candidateSpan;
    try {
        if (currentSize) refined.bytes.assign(current, current + currentSize);
        refined.candidateBitmap.assign(prior.candidateBitmap.size(), 0);
        for (size_t wordIndex = 0; wordIndex < prior.candidateBitmap.size(); ++wordIndex) {
            uint64_t word = prior.candidateBitmap[wordIndex];
            while (word) {
                const unsigned bit = std::countr_zero(word);
                const size_t offset = wordIndex * 64 + bit;
                word &= word - 1;
                if (offset >= prior.candidateSpan ||
                    offset > currentSize || width > currentSize - offset ||
                    offset > prior.bytes.size() || width > prior.bytes.size() - offset)
                    continue;
                if (!predicateUnchecked(config, current + offset,
                                        prior.bytes.data() + offset, width))
                    continue;
                refined.candidateBitmap[wordIndex] |= uint64_t{1} << bit;
                ++refined.candidateCount;
            }
        }
    } catch (const std::bad_alloc&) {
        setError(error, "not enough memory to refine the scan chunk");
        return false;
    } catch (...) {
        setError(error, "scan chunk refinement failed");
        return false;
    }

    candidateCount_ -= prior.candidateCount;
    candidateCount_ += refined.candidateCount;
    chunks_[index] = std::move(refined);
    return true;
}

MemoryScanPage MemoryScanSnapshot::page(uint64_t first, size_t limit) const {
    MemoryScanPage result;
    result.total = candidateCount_;
    result.first = (std::min)(first, candidateCount_);
    result.next = result.first;
    if (!limit || result.first >= candidateCount_) return result;

    const uint64_t available = candidateCount_ - result.first;
    const size_t reserve = static_cast<size_t>((std::min<uint64_t>)(available, limit));
    result.matches.reserve(reserve);
    uint64_t skip = result.first;
    for (const MemoryScanChunk& chunk : chunks_) {
        if (skip >= chunk.candidateCount) {
            skip -= chunk.candidateCount;
            continue;
        }
        for (size_t wordIndex = 0; wordIndex < chunk.candidateBitmap.size(); ++wordIndex) {
            uint64_t word = chunk.candidateBitmap[wordIndex];
            const unsigned inWord = std::popcount(word);
            if (skip >= inWord) {
                skip -= inWord;
                continue;
            }
            while (word) {
                const unsigned bit = std::countr_zero(word);
                word &= word - 1;
                if (skip) {
                    --skip;
                    continue;
                }
                const size_t offset = wordIndex * 64 + bit;
                if (offset >= chunk.candidateSpan ||
                    offset > chunk.bytes.size() ||
                    elementSize_ > chunk.bytes.size() - offset)
                    continue;
                MemoryScanMatch match;
                match.address = chunk.base + offset;
                match.bytes.assign(chunk.bytes.begin() + offset,
                                   chunk.bytes.begin() + offset + elementSize_);
                result.matches.push_back(std::move(match));
                if (result.matches.size() >= limit) {
                    result.next = result.first + result.matches.size();
                    result.hasMore = result.next < candidateCount_;
                    return result;
                }
            }
        }
    }
    result.next = result.first + result.matches.size();
    result.hasMore = result.next < candidateCount_;
    return result;
}

} // namespace ds
