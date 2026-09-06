// Pure tests for the paused debugger register editor.  Text inputs are encoded
// as target-side NUL-terminated buffers; the register receives their address.
#include "Core/RegisterEdit.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(condition) do { if (!(condition)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #condition); ++g_fail; \
} } while (0)

static bool bytesEqual(const RegisterEditValue& value,
                       std::initializer_list<uint8_t> expected) {
    return value.bytes == std::vector<uint8_t>(expected);
}

int main() {
    {
        const RegisterEditValue edit = ParseRegisterEdit("10");
        CHECK(edit.valid());
        CHECK(edit.kind == RegisterEditKind::HexValue);
        CHECK(edit.value == 0x10); // preserve the old editor's bare-hex behavior
        CHECK(edit.bytes.empty());
    }
    {
        const RegisterEditValue edit = ParseRegisterEdit("  0xFFFFFFFFFFFFFFFF  ");
        CHECK(edit.valid());
        CHECK(edit.kind == RegisterEditKind::HexValue);
        CHECK(edit.value == UINT64_MAX);
    }
    {
        const RegisterEditValue negative = ParseRegisterEdit("-1");
        CHECK(negative.value == UINT64_MAX && negative.negativeLiteral);
        CHECK(RegisterEditValueForTarget(negative, true) == UINT32_MAX);
    }
    CHECK(ParseRegisterEdit("+0x10").value == 0x10);
    CHECK(!ParseRegisterEdit("-not-a-number").valid());
    CHECK(!ParseRegisterEdit("").valid());
    CHECK(!ParseRegisterEdit("0x").valid());
    CHECK(!ParseRegisterEdit("0xnot_hex").valid());
    CHECK(!ParseRegisterEdit("10000000000000000").valid());

    {
        const RegisterEditValue edit = ParseRegisterEdit("this is some text");
        CHECK(edit.kind == RegisterEditKind::Utf8Text);
        CHECK(std::string(edit.bytes.begin(), edit.bytes.end() - 1) ==
              "this is some text");
        CHECK(!edit.bytes.empty() && edit.bytes.back() == 0);
    }
    {
        // Quoting makes a hex-looking value unambiguously text.
        const RegisterEditValue edit = ParseRegisterEdit("\"deadbeef\"");
        CHECK(edit.kind == RegisterEditKind::Utf8Text);
        CHECK(bytesEqual(edit, {'d','e','a','d','b','e','e','f',0}));
    }
    {
        const RegisterEditValue edit = ParseRegisterEdit("\"A\\nB\\x21\\0C\"");
        CHECK(edit.kind == RegisterEditKind::Utf8Text);
        CHECK(bytesEqual(edit, {'A','\n','B','!',0,'C',0}));
    }
    CHECK(!ParseRegisterEdit("\"unterminated").valid());
    CHECK(!ParseRegisterEdit("\"bad\\q\"").valid());
    CHECK(!ParseRegisterEdit("\"bad\\x4\"").valid());

    {
        const std::string omega = "\xCE\xA9";
        const RegisterEditValue edit = ParseRegisterEdit(
            std::string("L\"A\\n") + omega + "\"");
        CHECK(edit.kind == RegisterEditKind::Utf16Text);
        CHECK(bytesEqual(edit, {0x41,0x00, 0x0A,0x00, 0xA9,0x03, 0x00,0x00}));
    }
    {
        const std::string emoji = "\xF0\x9F\x98\x80";
        const RegisterEditValue edit = ParseRegisterEdit(
            std::string("u16\"") + emoji + "\"");
        CHECK(edit.kind == RegisterEditKind::Utf16Text);
        CHECK(bytesEqual(edit, {0x3D,0xD8, 0x00,0xDE, 0x00,0x00}));
    }
    {
        const std::string invalidWide = std::string("L\"") +
                                        static_cast<char>(0xFF) + "\"";
        CHECK(!ParseRegisterEdit(invalidWide).valid());
    }
    {
        // Strict UTF-8 validation for the UTF-16LE form: truncated/bad
        // continuations, overlong encodings, surrogate scalars and > U+10FFFF.
        const std::vector<std::string> invalidUtf8 = {
            std::string("\xE2\x82", 2),
            std::string("\xE2\x28\xA1", 3),
            std::string("\xE0\x80\x80", 3),
            std::string("\xED\xA0\x80", 3),
            std::string("\xF4\x90\x80\x80", 4),
        };
        for (const std::string& bytes : invalidUtf8)
            CHECK(!ParseRegisterEdit(std::string("L\"") + bytes + "\"").valid());
    }

    {
        std::string largest(kRegisterEditMaxBufferBytes - 1, 'g');
        const RegisterEditValue edit = ParseRegisterEdit(largest);
        CHECK(edit.valid());
        CHECK(edit.bytes.size() == kRegisterEditMaxBufferBytes);
        largest.push_back('g');
        CHECK(!ParseRegisterEdit(largest).valid());
    }
    {
        const size_t maxWideChars =
            (kRegisterEditMaxBufferBytes - 2) / sizeof(uint16_t);
        std::string largestWide = "L\"" + std::string(maxWideChars, 'w') + "\"";
        const RegisterEditValue edit = ParseRegisterEdit(largestWide);
        CHECK(edit.valid());
        CHECK(edit.bytes.size() == kRegisterEditMaxBufferBytes);
        largestWide.insert(largestWide.size() - 1, 1, 'w');
        CHECK(!ParseRegisterEdit(largestWide).valid());
    }
    {
        // Oversized public-parser input must fail before copying or reserving
        // based on its full size.
        const std::string oversized(kRegisterEditMaxInputBytes + 1, 'g');
        CHECK(!ParseRegisterEdit(oversized).valid());
    }

    CHECK(RegisterCanHoldTextPointer("rax", false));
    CHECK(RegisterCanHoldTextPointer("rax", true));
    CHECK(RegisterCanHoldTextPointer("r15", false));
    CHECK(!RegisterCanHoldTextPointer("r15", true));
    CHECK(!RegisterCanHoldTextPointer("rip", false));
    CHECK(!RegisterCanHoldTextPointer("rsp", false));
    CHECK(!RegisterCanHoldTextPointer("rbp", false));
    CHECK(!RegisterCanHoldTextPointer("rflags", false));
    CHECK(RegisterValueFitsTarget(UINT32_MAX, true));
    CHECK(!RegisterValueFitsTarget(static_cast<uint64_t>(UINT32_MAX) + 1, true));
    CHECK(RegisterValueFitsTarget(UINT64_MAX, false));

    if (g_fail == 0) std::puts("register_edit_test: OK");
    return g_fail ? 1 : 0;
}
