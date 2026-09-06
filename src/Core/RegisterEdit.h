#pragma once
//
// RegisterEdit.h
// Pure parsing/encoding helpers for the paused debugger's register editor.
// A CPU register can hold an integer or pointer, not an arbitrary string.  Text
// edits therefore produce a NUL-terminated target buffer; Debugger installs the
// resulting address in the selected data register.

#include <charconv>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace ds {

inline constexpr size_t kRegisterEditMaxBufferBytes = 64u * 1024u;
// A quoted byte can occupy four source characters (\xNN).  Bound the source
// before any copy/reserve while still allowing a maximum-size escaped payload.
inline constexpr size_t kRegisterEditMaxInputBytes =
    kRegisterEditMaxBufferBytes * 4u + 16u;

enum class RegisterEditKind {
    Invalid,
    HexValue,
    Utf8Text,
    Utf16Text,
};

struct RegisterEditValue {
    RegisterEditKind kind = RegisterEditKind::Invalid;
    uint64_t value = 0;
    bool negativeLiteral = false; // permits -1 -> EAX=FFFFFFFF on WOW64
    // Text payload encoded exactly as it will be stored in the target.  UTF-8
    // has one trailing zero byte; UTF-16LE has one trailing zero code unit.
    std::vector<uint8_t> bytes;
    std::string error;

    bool valid() const { return kind != RegisterEditKind::Invalid; }
    bool isText() const {
        return kind == RegisterEditKind::Utf8Text ||
               kind == RegisterEditKind::Utf16Text;
    }
};

namespace register_edit_detail {

inline std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' ||
                              value.front() == '\r' || value.front() == '\n'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' ||
                              value.back() == '\r' || value.back() == '\n'))
        value.remove_suffix(1);
    return value;
}

inline RegisterEditValue fail(std::string message) {
    RegisterEditValue result;
    result.error = std::move(message);
    return result;
}

inline int hexDigit(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

inline bool allHex(std::string_view value) {
    if (value.empty()) return false;
    for (char ch : value)
        if (hexDigit(ch) < 0) return false;
    return true;
}

inline bool decodeQuoted(std::string_view quoted, std::string& decoded,
                         std::string& error) {
    if (quoted.size() < 2 ||
        (quoted.front() != '"' && quoted.front() != '\'')) {
        error = "quoted text must start with a quote";
        return false;
    }
    const char quote = quoted.front();
    if (quoted.back() != quote) {
        error = "quoted text is missing its closing quote";
        return false;
    }

    decoded.clear();
    decoded.reserve(quoted.size() - 2);
    for (size_t i = 1; i + 1 < quoted.size(); ++i) {
        const char ch = quoted[i];
        if (ch == quote) {
            error = "an inner quote must be escaped";
            return false;
        }
        if (ch != '\\') {
            decoded.push_back(ch);
            continue;
        }
        if (++i + 1 >= quoted.size()) {
            error = "text ends with an incomplete escape";
            return false;
        }
        switch (quoted[i]) {
        case '\\': decoded.push_back('\\'); break;
        case '"':  decoded.push_back('"');  break;
        case '\'': decoded.push_back('\''); break;
        case 'n':  decoded.push_back('\n'); break;
        case 'r':  decoded.push_back('\r'); break;
        case 't':  decoded.push_back('\t'); break;
        case '0':  decoded.push_back('\0'); break;
        case 'x': {
            if (i + 2 >= quoted.size() - 1) {
                error = "\\x escapes require exactly two hex digits";
                return false;
            }
            const int hi = hexDigit(quoted[i + 1]);
            const int lo = hexDigit(quoted[i + 2]);
            if (hi < 0 || lo < 0) {
                error = "\\x escapes require exactly two hex digits";
                return false;
            }
            decoded.push_back(static_cast<char>((hi << 4) | lo));
            i += 2;
            break;
        }
        default:
            error = "unsupported text escape (use \\n, \\r, \\t, \\0, \\\\, or \\xNN)";
            return false;
        }
    }
    return true;
}

inline bool appendUtf16Le(std::string_view utf8, std::vector<uint8_t>& output,
                          std::string& error) {
    output.clear();
    // Do not reserve from attacker-controlled input before the 64 KiB output
    // limit has been established.  UTF-8 is commonly larger than its UTF-16
    // representation, so this remains a useful bounded reservation.
    output.reserve((std::min)(kRegisterEditMaxBufferBytes,
                              utf8.size() + size_t{2}));
    size_t at = 0;
    while (at < utf8.size()) {
        const uint8_t first = static_cast<uint8_t>(utf8[at]);
        uint32_t codepoint = 0;
        size_t length = 0;
        if (first < 0x80) {
            codepoint = first;
            length = 1;
        } else if (first >= 0xC2 && first <= 0xDF) {
            codepoint = first & 0x1Fu;
            length = 2;
        } else if (first >= 0xE0 && first <= 0xEF) {
            codepoint = first & 0x0Fu;
            length = 3;
        } else if (first >= 0xF0 && first <= 0xF4) {
            codepoint = first & 0x07u;
            length = 4;
        } else {
            error = "wide text contains invalid UTF-8";
            return false;
        }
        if (length > utf8.size() - at) {
            error = "wide text ends inside a UTF-8 character";
            return false;
        }
        for (size_t i = 1; i < length; ++i) {
            const uint8_t continuation = static_cast<uint8_t>(utf8[at + i]);
            if ((continuation & 0xC0u) != 0x80u) {
                error = "wide text contains invalid UTF-8";
                return false;
            }
            codepoint = (codepoint << 6) | (continuation & 0x3Fu);
        }
        // Reject overlong encodings, UTF-16 surrogate scalar values, and values
        // outside Unicode.  These checks also cover E0/ED/F0/F4 boundary cases.
        const uint32_t minimum = length == 1 ? 0u :
                                 length == 2 ? 0x80u :
                                 length == 3 ? 0x800u : 0x10000u;
        if (codepoint < minimum || codepoint > 0x10FFFFu ||
            (codepoint >= 0xD800u && codepoint <= 0xDFFFu)) {
            error = "wide text contains invalid UTF-8";
            return false;
        }

        auto appendUnit = [&](uint16_t unit) {
            output.push_back(static_cast<uint8_t>(unit & 0xFFu));
            output.push_back(static_cast<uint8_t>(unit >> 8));
        };
        if (codepoint <= 0xFFFFu) {
            appendUnit(static_cast<uint16_t>(codepoint));
        } else {
            codepoint -= 0x10000u;
            appendUnit(static_cast<uint16_t>(0xD800u + (codepoint >> 10)));
            appendUnit(static_cast<uint16_t>(0xDC00u + (codepoint & 0x3FFu)));
        }
        if (output.size() > kRegisterEditMaxBufferBytes - 2) {
            error = "text is larger than the 64 KiB register-buffer limit";
            return false;
        }
        at += length;
    }
    output.push_back(0);
    output.push_back(0);
    return true;
}

inline RegisterEditValue makeText(std::string text, bool wide) {
    RegisterEditValue result;
    if (wide) {
        if (!appendUtf16Le(text, result.bytes, result.error)) return result;
        result.kind = RegisterEditKind::Utf16Text;
        return result;
    }
    if (text.size() >= kRegisterEditMaxBufferBytes) {
        result.error = "text is larger than the 64 KiB register-buffer limit";
        return result;
    }
    result.bytes.assign(text.begin(), text.end());
    result.bytes.push_back(0);
    result.kind = RegisterEditKind::Utf8Text;
    return result;
}

} // namespace register_edit_detail

// Accepted forms:
//   1234 / 0x1234 / -1   raw hexadecimal register value (legacy behavior)
//   this is text         UTF-8/byte C string; surrounding whitespace is trimmed
//   "text\\n"            quoted UTF-8/byte C string with C-style escapes
//   L"wide text"         quoted UTF-16LE C string
// Quote a hex-only string ("deadbeef") to prevent it being parsed as a value.
inline RegisterEditValue ParseRegisterEdit(std::string_view input) {
    using namespace register_edit_detail;
    if (input.size() > kRegisterEditMaxInputBytes)
        return fail("register edit input is larger than the bounded parser limit");
    input = trim(input);
    if (input.empty()) return fail("enter a hexadecimal value or text");

    bool wide = false;
    std::string_view quoted = input;
    if (input.size() >= 2 && input[0] == 'L' && input[1] == '"') {
        wide = true;
        quoted.remove_prefix(1);
    } else if (input.size() >= 4 && input.substr(0, 4) == "u16\"") {
        wide = true;
        quoted.remove_prefix(3);
    }
    if (!quoted.empty() && (quoted.front() == '"' || quoted.front() == '\'')) {
        std::string decoded, error;
        if (!decodeQuoted(quoted, decoded, error)) return fail(std::move(error));
        return makeText(std::move(decoded), wide);
    }
    if (wide) return fail("wide text must use L\"...\" or u16\"...\"");
    if (input.front() == '"' || input.front() == '\'' ||
        input.back() == '"' || input.back() == '\'')
        return fail("quoted text is missing its matching quote");

    std::string_view digits = input;
    const bool signedValue = digits.front() == '+' || digits.front() == '-';
    const bool negative = signedValue && digits.front() == '-';
    if (signedValue) digits.remove_prefix(1);
    const bool prefixed = digits.size() >= 2 && digits[0] == '0' &&
                          (digits[1] == 'x' || digits[1] == 'X');
    if (prefixed) digits.remove_prefix(2);
    if (signedValue || prefixed || allHex(digits)) {
        if (!allHex(digits))
            return fail(signedValue
                ? "a signed register value must contain only hexadecimal digits"
                : "0x must be followed by hexadecimal digits");
        uint64_t value = 0;
        const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(),
                                            value, 16);
        if (parsed.ec == std::errc::result_out_of_range)
            return fail("hexadecimal value does not fit in 64 bits");
        if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size())
            return fail("invalid hexadecimal register value");
        RegisterEditValue result;
        result.kind = RegisterEditKind::HexValue;
        result.value = negative ? uint64_t{0} - value : value;
        result.negativeLiteral = negative;
        return result;
    }

    return makeText(std::string(input), false);
}

// Text-pointer injection is intentionally limited to data GPRs.  Assigning a
// text address to IP, SP, frame pointer, or FLAGS would corrupt control state.
inline bool RegisterCanHoldTextPointer(std::string_view canonicalName,
                                       bool targetIs32Bit) {
    if (canonicalName == "rax" || canonicalName == "rbx" ||
        canonicalName == "rcx" || canonicalName == "rdx" ||
        canonicalName == "rsi" || canonicalName == "rdi")
        return true;
    if (targetIs32Bit) return false;
    return canonicalName == "r8"  || canonicalName == "r9"  ||
           canonicalName == "r10" || canonicalName == "r11" ||
           canonicalName == "r12" || canonicalName == "r13" ||
           canonicalName == "r14" || canonicalName == "r15";
}

inline bool RegisterValueFitsTarget(uint64_t value, bool targetIs32Bit) {
    return !targetIs32Bit || value <= UINT32_MAX;
}

inline uint64_t RegisterEditValueForTarget(const RegisterEditValue& edit,
                                           bool targetIs32Bit) {
    return targetIs32Bit && edit.negativeLiteral
         ? static_cast<uint32_t>(edit.value)
         : edit.value;
}

} // namespace ds
