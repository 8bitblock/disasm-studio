#pragma once
//
// jvm_testclass.h
// Shared synthetic .class builder for the JVM tests. Emits a small but fully
// valid class file ("Main" with a static main + a private static helper) whose
// bytecode exercises the interesting decoder paths: ldc of a string constant,
// a LOCAL invokestatic (branch-target resolution), bipush/iinc, goto, nops,
// and a tableswitch whose bci forces a non-zero alignment pad. The builder
// records both methods' code-array file offsets for the tests.
//
#include <cstdint>
#include <cstring>
#include <vector>

struct ClassBytes {
    std::vector<uint8_t> bytes;
    uint32_t mainCodeOff   = 0;   // file offset of main's first bytecode byte (41 bytes)
    uint32_t helperCodeOff = 0;   // file offset of helper's first bytecode byte (3 bytes)
};

namespace jvmtest {

struct W {
    std::vector<uint8_t>& b;
    void u1(uint8_t v)  { b.push_back(v); }
    void u2(uint16_t v) { b.push_back((uint8_t)(v >> 8)); b.push_back((uint8_t)v); }
    void u4(uint32_t v) {
        b.push_back((uint8_t)(v >> 24)); b.push_back((uint8_t)(v >> 16));
        b.push_back((uint8_t)(v >> 8));  b.push_back((uint8_t)v);
    }
    void raw(const void* p, size_t n) {
        const uint8_t* q = (const uint8_t*)p;
        b.insert(b.end(), q, q + n);
    }
    void utf8(const char* s) { u1(1); u2((uint16_t)std::strlen(s)); raw(s, std::strlen(s)); }
};

// main's 41 bytes of code (bci comments inline):
//   0: ldc #2 ("Hello")        2: invokestatic #12 (Main.helper)
//   5: bipush 7                7: iinc 1, 1
//  10: goto -> 16             13..15: nop
//  16: iconst_0               17: tableswitch (pad 2; 0->16, 1->13, default->13)
//  40: return
inline void emitMainCode(W& w) {
    const uint8_t code[] = {
        0x12, 0x02,
        0xB8, 0x00, 0x0C,
        0x10, 0x07,
        0x84, 0x01, 0x01,
        0xA7, 0x00, 0x06,
        0x00, 0x00, 0x00,
        0x03,
        0xAA, 0x00, 0x00,                  // tableswitch + 2 pad bytes
        0xFF, 0xFF, 0xFF, 0xFC,            // default: -4  -> bci 13
        0x00, 0x00, 0x00, 0x00,            // low  = 0
        0x00, 0x00, 0x00, 0x01,            // high = 1
        0xFF, 0xFF, 0xFF, 0xFF,            // case 0: -1 -> bci 16
        0xFF, 0xFF, 0xFF, 0xFC,            // case 1: -4 -> bci 13
        0xB1,
    };
    static_assert(sizeof(code) == 41, "main bytecode must be 41 bytes");
    w.raw(code, sizeof(code));
}

inline ClassBytes buildTestClass() {
    ClassBytes out;
    W w{out.bytes};

    w.u4(0xCAFEBABE);
    w.u2(0);                       // minor
    w.u2(52);                      // major (Java 8)

    // ---- constant pool (count 29; Long pads slot 21, Double pads slot 28) ----
    w.u2(29);
    w.utf8("Hello");                                   // 1
    w.u1(8); w.u2(1);                                  // 2  String #1
    w.utf8("Main");                                    // 3
    w.u1(7); w.u2(3);                                  // 4  Class #3 (this)
    w.utf8("java/lang/Object");                        // 5
    w.u1(7); w.u2(5);                                  // 6  Class #5 (super)
    w.utf8("main");                                    // 7
    w.utf8("([Ljava/lang/String;)V");                  // 8
    w.utf8("helper");                                  // 9
    w.utf8("()I");                                     // 10
    w.u1(12); w.u2(9); w.u2(10);                       // 11 NameAndType helper:()I
    w.u1(10); w.u2(4); w.u2(11);                       // 12 Methodref Main.helper:()I (LOCAL)
    w.utf8("java/io/PrintStream");                     // 13
    w.u1(7); w.u2(13);                                 // 14 Class #13
    w.utf8("println");                                 // 15
    w.utf8("(Ljava/lang/String;)V");                   // 16
    w.u1(12); w.u2(15); w.u2(16);                      // 17 NameAndType println:(...)V
    w.u1(10); w.u2(14); w.u2(17);                      // 18 Methodref PrintStream.println
    w.u1(3); w.u4(42);                                 // 19 Integer 42
    w.u1(5); w.u4(0); w.u4(123456789);                 // 20 Long 123456789 (slot 21 pads)
    w.utf8("Code");                                    // 22
    w.utf8("SourceFile");                              // 23
    w.utf8("Main.java");                               // 24
    w.utf8("LineNumberTable");                         // 25
    { w.u1(4); float f = 2.5f; uint32_t v; std::memcpy(&v, &f, 4); w.u4(v); }   // 26 Float
    { w.u1(6); double d = 3.5; uint64_t v; std::memcpy(&v, &d, 8);             // 27 Double (28 pads)
      w.u4((uint32_t)(v >> 32)); w.u4((uint32_t)v); }

    w.u2(0x0021);                  // ACC_PUBLIC | ACC_SUPER
    w.u2(4);                       // this  = Class Main
    w.u2(6);                       // super = Class Object
    w.u2(0);                       // interfaces
    w.u2(0);                       // fields

    // ---- methods ----
    w.u2(2);

    // main: public static, one Code attribute (no nested attrs, no handlers)
    w.u2(0x0009); w.u2(7); w.u2(8); w.u2(1);
    w.u2(22);                      // "Code"
    w.u4(2 + 2 + 4 + 41 + 2 + 2); // max_stack+max_locals+code_len+code+exc+attrs
    w.u2(2);                       // max_stack
    w.u2(2);                       // max_locals
    w.u4(41);
    out.mainCodeOff = (uint32_t)out.bytes.size();
    emitMainCode(w);
    w.u2(0);                       // exception table: none
    w.u2(0);                       // nested attributes: none

    // helper: private static, Code with one handler + a LineNumberTable
    w.u2(0x000A); w.u2(9); w.u2(10); w.u2(1);
    w.u2(22);                      // "Code"
    w.u4(2 + 2 + 4 + 3 + 2 + 8 + 2 + (2 + 4 + 2 + 8));
    w.u2(1);                       // max_stack
    w.u2(0);                       // max_locals
    w.u4(3);
    out.helperCodeOff = (uint32_t)out.bytes.size();
    w.u1(0x10); w.u1(42);          // bipush 42
    w.u1(0xAC);                    // ireturn
    w.u2(1);                       // exception table: 1 entry
    w.u2(0); w.u2(2); w.u2(2); w.u2(0);   // start, end, handler, catch-all
    w.u2(1);                       // nested attributes: 1
    w.u2(25);                      // "LineNumberTable"
    w.u4(2 + 8);
    w.u2(2);                       // 2 entries
    w.u2(0); w.u2(10);             // pc 0 -> line 10
    w.u2(2); w.u2(11);             // pc 2 -> line 11

    // ---- class attributes: SourceFile ----
    w.u2(1);
    w.u2(23);                      // "SourceFile"
    w.u4(2);
    w.u2(24);                      // "Main.java"

    return out;
}

} // namespace jvmtest
