#pragma once
#include "../Disasm/IDisassembler.h"
#include <string>
#include <string_view>

namespace ds {

// Display-only wording for GmlDisassembler output. Never changes decoder fields,
// references, control-flow authority, or claims to reconstruct runtime stack values.
struct GmlInstructionText {
    std::string operation;
    std::string operands;
    std::string explanation;
};

namespace gml_text_detail {
inline std::string_view TypeName(char type) {
    switch (type) {
    case 'd': return "64-bit floating-point number";
    case 'f': return "32-bit floating-point number";
    case 'i': return "32-bit signed integer";
    case 'l': return "64-bit signed integer";
    case 'b': return "boolean (true or false)";
    case 'v': return "dynamic GameMaker value (its type is carried with the value)";
    case 's': return "string (text)";
    case 'e': return "signed 16-bit immediate, used as a 32-bit integer";
    default: return "unknown value type";
    }
}

inline void ExplainTypes(std::string& text, char first, char second) {
    if (!first) return;
    text += " Type: .";
    text += first;
    text += " = ";
    text += TypeName(first);
    if (second && second != first) {
        text += "; .";
        text += second;
        text += " = ";
        text += TypeName(second);
    }
    text += '.';
}

inline void ExplainReference(std::string& text, const Instruction& in) {
    if (in.operands.starts_with("unresolved "))
        text += " The archive has not resolved the referenced name.";
    if (in.operands.find(" [mode=") != std::string::npos)
        text += " The reference mode may use additional instance or array values from the temporary stack; their values are not known here.";
}

inline std::string ArgumentText(std::string operands) {
    const size_t marker = operands.rfind(" (argc=");
    const bool indirect = marker == std::string::npos && operands.starts_with("argc=");
    if (!indirect && marker == std::string::npos) return operands;
    const size_t start = indirect ? 0 : marker + 2;
    size_t end = start + 5;
    while (end < operands.size() && operands[end] >= '0' && operands[end] <= '9') ++end;
    if (end == start + 5) return operands;
    if (indirect ? end != operands.size() : end + 1 != operands.size() || operands[end] != ')') return operands;
    const std::string count = operands.substr(start + 5, end - start - 5);
    operands.replace(start, end - start, count + (count == "1" ? " argument" : " arguments"));
    return operands;
}
} // namespace gml_text_detail

// Semantics checked against the primary decoder/decompiler implementations:
// https://github.com/UnderminersTeam/Underanalyzer/blob/main/Underanalyzer/VMData.cs
// https://github.com/UnderminersTeam/Underanalyzer/blob/main/Underanalyzer/Decompiler/AST/BlockSimulator.cs
// https://github.com/UnderminersTeam/UndertaleModTool/blob/master/UndertaleModLib/Models/UndertaleCode.cs
// This is an explanation of one decoded instruction, not a GML decompiler.
inline GmlInstructionText DescribeGmlInstruction(const Instruction& in) {
    using namespace gml_text_detail;
    GmlInstructionText result{in.mnemonic, in.operands, {}};
    const std::string_view mnemonic = in.mnemonic;
    if (mnemonic == "gml.unsupported" || mnemonic == "break.unsupported") {
        result.operation = "Unsupported instruction";
        result.explanation = "The bytecode operation is not understood; its effects are unknown.";
        return result;
    }
    const bool popSwap = mnemonic.starts_with("pop.swap.");
    const size_t split = mnemonic.find('.', popSwap ? 4 : 0);
    const std::string_view op = mnemonic.substr(0, split);
    const char first = split != std::string_view::npos && split + 1 < mnemonic.size() ? mnemonic[split + 1] : 0;
    const char second = split != std::string_view::npos && split + 3 < mnemonic.size() && mnemonic[split + 2] == '.' ? mnemonic[split + 3] : 0;
    auto describe = [&](const char* operation, const char* explanation) {
        result.operation = operation;
        result.explanation = explanation;
    };
    const bool push = op == "push" || op == "pushi" || op == "pushloc" || op == "pushglb" || op == "pushbltn";
    if (push) {
        if (in.comment.starts_with("FUNC #")) {
            describe("Load function reference", "Keep a reference to this function as a temporary value for later use.");
        } else if (first == 'i' && in.comment.starts_with("VARI #")) {
            describe("Load variable identifier", "Keep the variable's encoded identifier as a temporary value; this does not read the variable's contents.");
        } else if (first == 'v') {
            describe("Read variable", "Read this variable and keep its value on the temporary stack for the next operations.");
            ExplainReference(result.explanation, in);
        } else {
            describe("Load constant", "Keep this constant on the temporary stack for the next operations.");
            if (first == 's' && in.operands.starts_with("STRG #")) {
                if (in.comment.size() >= 2 && in.comment.front() == '"' && in.comment.back() == '"')
                    result.operands = in.comment;
                else
                    result.explanation += " The string's text is unresolved; only its table index is available.";
            }
        }
    } else if (op == "pop.swap") {
        describe("Reorder temporary values", "Rearrange values on the temporary stack using the encoded swap size.");
        result.explanation += " The .e suffix selects this special stack operation; it does not write a variable.";
        return result;
    } else if (op == "pop") {
        describe("Write variable", "Take the prepared value from the temporary stack and assign it to this variable.");
        ExplainReference(result.explanation, in);
    } else if (op == "popz") {
        describe("Discard value", "Remove the most recent temporary value because it is no longer needed.");
    } else if (op == "conv") {
        describe("Convert value", "Convert the most recent temporary value to another value type.");
        result.operands = std::string(TypeName(first)) + " -> " + std::string(TypeName(second));
    } else if (op == "dup") {
        bool rearrange = first == 'e' || in.operands.find("move=") != std::string::npos;
        for (const auto& operand : in.typedOperands) {
            if (operand.kind != OperandKind::Immediate) continue;
            const unsigned size = static_cast<unsigned>(operand.immediate & 255);
            const unsigned moveSize = static_cast<unsigned>((operand.immediate >> 11) & 15);
            rearrange = first == 'e' ? size != 0 : moveSize != 0;
            break;
        }
        if (rearrange) {
            describe("Reorder temporary values", "Use the encoded sizes to rearrange groups on the temporary stack; some encodings leave it unchanged.");
        } else {
            describe("Copy temporary values", "Duplicate the encoded amount of temporary stack data so it can be used again. The amount depends on the value type and size operand.");
        }
        if (first == 'e') {
            result.explanation += " The .e suffix selects a special encoding for dynamic GameMaker values.";
            return result;
        }
    } else if (op == "b") {
        describe("Jump", "Continue execution at the destination shown.");
    } else if (op == "bt") {
        describe("Jump if true", "Consume the most recent temporary condition; jump when true, otherwise continue with the next instruction.");
    } else if (op == "bf") {
        describe("Jump if false", "Consume the most recent temporary condition; jump when false, otherwise continue with the next instruction.");
    } else if (op == "pushenv") {
        describe("Begin with loop", "Enter a GML with context using the prepared instance selection; skip to the destination if there is no matching instance.");
    } else if (op == "popenv") {
        if (in.operands == "exit") {
            describe("Leave with loop", "Leave the current GML with context and continue with the next instruction.");
            result.operands.clear();
        } else {
            describe("Next with instance", "Jump back for another instance in the GML with loop; when finished, leave the context and continue.");
        }
    } else if (op == "call") {
        describe("Call function", "Call this function with arguments prepared on the temporary stack and keep its returned value.");
        result.operands = ArgumentText(in.operands);
        ExplainReference(result.explanation, in);
    } else if (op == "callv") {
        describe("Call function value", "Use the function reference and self instance prepared on the temporary stack to call a function with the prepared arguments.");
        result.operands = ArgumentText(in.operands);
    } else if (op == "ret") {
        describe("Return value", "Finish this function and return the most recent temporary value to its caller.");
    } else if (op == "exit") {
        describe("Return without value", "Finish this function, script, or event without an explicit return value.");
    } else if (op == "cmp") {
        const std::string_view comparison = in.operands;
        const char* symbol = comparison == "lt" ? "<" : comparison == "lte" ? "<=" : comparison == "eq" ? "==" :
            comparison == "neq" ? "!=" : comparison == "gte" ? ">=" : comparison == "gt" ? ">" : nullptr;
        if (symbol) {
            describe("Compare values", "Compare the preceding temporary value (left) with the most recent one (right), then keep a true/false result.");
            result.operands = std::string("left ") + symbol + " right";
        } else {
            describe("Unknown comparison", "The comparison kind is unsupported; the condition it computes is unknown.");
        }
    } else if (op == "add") {
        describe("Add values", "Add the two most recent temporary values and keep the result; GameMaker also uses this operation to join strings.");
    } else if (op == "sub") {
        describe("Subtract values", "Subtract the most recent temporary value from the preceding one and keep the result.");
    } else if (op == "mul") {
        describe("Multiply values", "Multiply the two most recent temporary values and keep the result.");
    } else if (op == "div") {
        describe("Divide values", "Divide the preceding temporary value by the most recent one and keep the result.");
    } else if (op == "rem") {
        describe("Integer divide", "Apply GML div to the preceding and most recent temporary values, keeping the whole-number quotient.");
    } else if (op == "mod") {
        describe("Find remainder", "Apply GML mod (%) to the preceding and most recent temporary values and keep the remainder.");
    } else if (op == "neg") {
        describe("Negate value", "Change the sign of the most recent temporary value.");
    } else if (op == "not") {
        if (first == 'b') describe("Logical NOT", "Reverse the most recent temporary condition: true becomes false, and false becomes true.");
        else describe("Invert value", "Apply NOT to the most recent temporary value; the encoded type determines boolean or bitwise behavior.");
    } else if (op == "and" || op == "or" || op == "xor") {
        result.operation = op == "and" ? "Combine with AND" : op == "or" ? "Combine with OR" : "Combine with XOR";
        result.explanation = "Combine the two most recent temporary values and keep the result; the encoded types determine boolean or bitwise behavior.";
    } else if (op == "shl") {
        describe("Shift bits left", "Shift the preceding temporary value left by the most recent value's bit count and keep the result.");
    } else if (op == "shr") {
        describe("Shift bits right", "Shift the preceding temporary value right by the most recent value's bit count and keep the result.");
    } else if (op == "chkindex") {
        describe("Check array index", "Check the prepared array index against the allowed bounds.");
    } else if (op == "pushaf") {
        describe("Read array element", "Use the prepared array reference and index to read the final indexed value of a multidimensional array.");
    } else if (op == "popaf") {
        describe("Write array element", "Use the prepared array reference, index, and value to assign an array element.");
    } else if (op == "pushac") {
        describe("Read nested array", "Use the prepared array reference and index to obtain an inner array reference for further indexing.");
    } else if (op == "setowner") {
        describe("Set array owner", "Use a prepared value to set array copy-on-write ownership bookkeeping.");
    } else if (op == "isstaticok") {
        describe("Check static initialization", "Keep a true/false result indicating whether this function's static initialization has been marked as done.");
    } else if (op == "setstatic") {
        describe("Mark static initialization", "Mark this function's static initialization so the runtime does not enter it again.");
    } else if (op == "savearef") {
        describe("Save array reference", "Temporarily retain the prepared array reference for a later array operation.");
    } else if (op == "restorearef") {
        describe("Restore array reference", "Restore the array reference retained by the matching save operation.");
    } else if (op == "chknullish") {
        describe("Check for missing value", "Test whether the prepared value is nullish, such as undefined or pointer_null, and keep a true/false result.");
    } else if (op == "pushref") {
        describe("Load reference", "Keep the encoded asset or function reference as a temporary value. An unresolved numeric reference does not identify a particular asset here.");
        if (in.comment.starts_with("FUNC #")) result.operation = "Load function reference";
    } else {
        describe("Unknown instruction", "No readable interpretation is available for this operation; consult the raw instruction.");
        return result;
    }
    if ((op == "b" || op == "bt" || op == "bf" || op == "pushenv" || op == "popenv") &&
        in.operands != "exit" && !in.flow.directTargetValid && !in.branchTargetValid)
        result.explanation += " The decoder could not validate its destination.";
    ExplainTypes(result.explanation, first, second);
    return result;
}
} // namespace ds
