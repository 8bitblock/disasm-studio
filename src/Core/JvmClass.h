#pragma once
//
// JvmClass.h
// Java .class file parser: constant pool, fields, methods, and each method's
// Code attribute (recorded as FILE OFFSET + length into the original buffer so
// the loader can map bytecode regions and the disassembler can find method
// starts). Pure logic, bounded and hostile-input safe in the BinaryFile
// parser style: every read is cursor-checked, counts are capped, and a
// malformed file yields ok == false with a reason instead of UB.
//
// Used by: BinaryFile (BinFormat::JavaClass loading), JvmDisassembler
// (constant-pool operand symbolication, switch-padding bci math),
// FunctionAnalyzer (method table = authoritative function list).
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

// Constant-pool tags (JVMS 4.4).
enum : uint8_t {
    CP_Utf8 = 1, CP_Integer = 3, CP_Float = 4, CP_Long = 5, CP_Double = 6,
    CP_Class = 7, CP_String = 8, CP_Fieldref = 9, CP_Methodref = 10,
    CP_InterfaceMethodref = 11, CP_NameAndType = 12, CP_MethodHandle = 15,
    CP_MethodType = 16, CP_Dynamic = 17, CP_InvokeDynamic = 18,
    CP_Module = 19, CP_Package = 20,
};

// One constant-pool slot. Long/Double occupy two slots (the second is tag 0).
struct JvmCpEntry {
    uint8_t     tag = 0;
    uint16_t    a   = 0;     // first index operand (class_index / name_index / ...)
    uint16_t    b   = 0;     // second index operand (name_and_type_index / ...)
    uint8_t     kind = 0;    // CP_MethodHandle reference_kind
    int32_t     i32 = 0;     // CP_Integer
    int64_t     i64 = 0;     // CP_Long
    float       f32 = 0.0f;  // CP_Float
    double      f64 = 0.0;   // CP_Double
    std::string utf8;        // CP_Utf8 payload (raw modified-UTF8 bytes, capped)
};

struct JvmExceptionHandler {
    uint16_t startPC = 0, endPC = 0, handlerPC = 0;
    uint16_t catchTypeIndex = 0;   // 0 = catch-all (finally)
};

struct JvmMethod {
    std::string name;        // "<init>", "main", ...
    std::string descriptor;  // "([Ljava/lang/String;)V"
    uint16_t    accessFlags = 0;
    // Code attribute (zero codeLength = no body: abstract / native).
    uint32_t    codeOffset = 0;   // FILE OFFSET of the first bytecode byte
    uint32_t    codeLength = 0;
    uint16_t    maxStack = 0, maxLocals = 0;
    std::vector<JvmExceptionHandler> handlers;
    // LineNumberTable (start_pc -> source line), kept sorted by start_pc.
    std::vector<std::pair<uint16_t, uint16_t>> lineNumbers;
};

struct JvmField {
    std::string name, descriptor;
    uint16_t    accessFlags = 0;
};

// Method access flags we care about for display.
enum : uint16_t {
    JVM_ACC_PUBLIC = 0x0001, JVM_ACC_PRIVATE = 0x0002, JVM_ACC_PROTECTED = 0x0004,
    JVM_ACC_STATIC = 0x0008, JVM_ACC_FINAL = 0x0010, JVM_ACC_SYNCHRONIZED = 0x0020,
    JVM_ACC_NATIVE = 0x0100, JVM_ACC_ABSTRACT = 0x0400,
};

struct JvmClassFile {
    bool        ok = false;
    std::string error;           // parse-failure reason when !ok
    uint16_t    minorVersion = 0, majorVersion = 0;
    uint16_t    accessFlags  = 0;
    std::string thisClass;       // internal form: "com/example/Main"
    std::string superClass;
    std::string sourceFile;      // SourceFile attribute, may be empty
    std::vector<std::string> interfaces;
    std::vector<JvmCpEntry>  cp; // 1-based: cp[0] unused, Long/Double pad a slot
    std::vector<JvmField>    fields;
    std::vector<JvmMethod>   methods;

    // ---- constant-pool resolution helpers (all bounds-safe, "" on miss) ----
    const JvmCpEntry* at(uint16_t idx) const {
        return (idx > 0 && idx < cp.size()) ? &cp[idx] : nullptr;
    }
    std::string utf8At(uint16_t idx) const;        // CP_Utf8 payload
    std::string classNameAt(uint16_t idx) const;   // CP_Class -> its name
    // Human-readable text for any constant-pool index, used as the inline
    // disassembly comment: Methodref -> "java/io/PrintStream.println:(...)V",
    // String -> "\"...\"" (escaped, capped), Integer/Long/Float/Double ->
    // literal, Class -> name. "" for an out-of-range / unusable index.
    std::string describeCp(uint16_t idx) const;

    // The method whose [codeOffset, codeOffset+codeLength) contains `off`,
    // or null. Methods are non-overlapping by construction.
    const JvmMethod* methodAtOffset(uint64_t off) const;
    // Source line for a bytecode index inside `m` (LineNumberTable), 0 = none.
    static uint16_t lineForBci(const JvmMethod& m, uint32_t bci);
};

// True when the buffer starts with the 0xCAFEBABE magic and a plausible
// class-file version (45..99 covers JDK 1.0 .. far future).
bool IsJavaClassImage(const uint8_t* data, size_t n);

// Parse a .class image. Always returns a result; check `ok`/`error`.
JvmClassFile ParseJavaClass(const uint8_t* data, size_t n);

// Parse a bare constant-pool blob into `out.cp` (everything else untouched).
// `count` is the class-file-header style count (entries are 1..count-1). This
// is the exact shape of a JDWP ReferenceType::ConstantPool reply, so a live
// JVM debug session can symbolicate fetched bytecode without the .class file.
bool ParseConstantPoolOnly(const uint8_t* data, size_t n, uint16_t count, JvmClassFile& out);

// "([Ljava/lang/String;I)V" + "main" -> "void main(String[], int)".
// Best-effort pretty form for dividers/signatures; never fails.
std::string JvmPrettyMethod(const std::string& name, const std::string& descriptor);

// Short display name for a method: "Main.main" from "com/example/Main".
std::string JvmShortClassName(const std::string& internalName);

} // namespace ds
