#pragma once
//
// JvmAnnotate.h
// Java bytecode annotation engine. Given a parsed class file and one method's
// decoded instruction stream, it produces:
//   - a plain-language stack-effect gloss per instruction ("pushes the String
//     constant onto the operand stack", "calls static method, consumes 2
//     argument slot(s)", "branches if the top int is zero"),
//   - operand-stack depth before/after every instruction (abstract
//     interpretation over the bytecode CFG) for the stack-machine view,
//   - branch meaning for every conditional/goto/switch,
//   - the method's call graph edges (invoke* targets), field accesses
//     (get/put field/static), and referenced String constants,
//   - category findings (System.exit, input reading, file I/O, networking,
//     reflection, class loading, native/JNI, crypto, process spawn), and
//   - a "looks like a password / check / license method" verdict.
//
// Honesty contract (same as FuncAnnotate): every finding carries a confidence
// score, an evidence string, and the analyzer name. Pure logic — depends only
// on the decoded Instruction stream + JvmClassFile, so it unit-tests in the
// sandbox via JvmDisassembler exactly like jvmdisasm_test.
//
#include "JvmClass.h"
#include "../Disasm/IDisassembler.h"
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

// High-level capability category a method touches (drives the crackme/Java
// findings + the Game/Java context panels).
enum class JvmCat : uint8_t {
    None, Exit, Input, File, Network, Reflection, ClassLoad, Native, Crypto, Exec, Thread, Ui
};
const char* JvmCatName(JvmCat c);

// One annotation row, parallel to the method's decoded instruction list.
struct JvmInsnNote {
    uint64_t    bci = 0;          // bytecode index (== VA under the identity mapping)
    int         stackBefore = -1; // operand-stack depth (slots) on entry; -1 = unreached
    int         stackAfter  = -1; // ...on exit (-1 for terminators / unreached)
    std::string effect;          // plain-language stack effect ("" = self-evident)
    std::string branch;          // branch meaning ("branches if a == b"), "" if not a branch
};

// A call edge (invoke* / invokedynamic).
struct JvmCall {
    uint64_t    bci = 0;
    std::string kind;            // "virtual" / "static" / "special" / "interface" / "dynamic"
    std::string owner;           // "java/io/PrintStream" ("" for dynamic)
    std::string name;            // "println"
    std::string descriptor;      // "(Ljava/lang/String;)V"
    int         argSlots = 0;    // argument slots consumed (excluding objectref)
    int         retSlots = 0;    // result slots pushed
    bool        local = false;   // resolves to a method in THIS class (branchTarget set)
};

// A field read/write (getfield/putfield/getstatic/putstatic).
struct JvmFieldAccess {
    uint64_t    bci = 0;
    bool        put = false;     // putfield/putstatic vs get*
    bool        isStatic = false;// *static vs instance
    std::string owner, name, type;
};

// A String constant referenced by ldc / ldc_w.
struct JvmStringRef { uint64_t bci = 0; std::string text; };

// One category / check finding (confidence + evidence, never a fact).
struct JvmFinding {
    JvmCat      cat = JvmCat::None;
    std::string text;            // "reads user input (Scanner.nextLine)"
    std::string evidence;        // why
    float       confidence = 0.5f;
    uint64_t    bci = 0;         // representative instruction (0 = method-level)
};

struct JvmMethodAnalysis {
    std::string name, descriptor, pretty;
    uint16_t    accessFlags = 0;
    bool        isStatic = false, isNative = false, isAbstract = false;
    uint16_t    declaredMaxStack = 0, maxLocals = 0;
    int         computedMaxStack = 0;     // peak depth from abstract interpretation
    bool        stackConsistent = true;   // false if a merge saw conflicting depths (obfuscation?)
    std::vector<JvmInsnNote>     notes;   // parallel to the instruction list passed in
    std::vector<JvmCall>         calls;
    std::vector<JvmFieldAccess>  fields;
    std::vector<JvmStringRef>    strings;
    std::vector<JvmFinding>      findings;
    bool        likelyCheck = false;      // password / serial / license / auth check?
    float       checkConfidence = 0.0f;
    std::string checkEvidence;
    std::string summary;                  // one-liner for the method divider
    const char* analyzer = "JvmAnnotate";
};

// Analyze one method. `insns` must be its decoded bytecode (e.g. from
// JvmDisassembler with the class attached), in address order; bci = VA.
JvmMethodAnalysis AnalyzeJvmMethod(const JvmClassFile& cf, const JvmMethod& m,
                                   const std::vector<Instruction>& insns);

// ---- pure helpers, exposed for the UI + tests --------------------------------

// Argument slots and return slots of a method descriptor "(args)ret"
// (long/double = 2 slots, void return = 0). Returns false on a malformed
// descriptor (out params zeroed).
bool JvmDescriptorSlots(const std::string& descriptor, int& argSlots, int& retSlots);

// Net operand-stack slot delta of one decoded instruction, plus a plain-language
// effect string. `cf` resolves invoke/field descriptors and ldc constants.
// `terminator` is set for *return/athrow (stack depth becomes undefined after).
struct JvmStackEffect { int delta = 0; bool terminator = false; std::string effect; };
JvmStackEffect JvmInstrStackEffect(const JvmClassFile& cf, const Instruction& in);

// Plain-language meaning of a JVM branch/goto/switch ("" if not a branch).
std::string JvmBranchMeaning(const Instruction& in);

} // namespace ds
