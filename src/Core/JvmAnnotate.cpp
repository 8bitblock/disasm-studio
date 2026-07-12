//
// JvmAnnotate.cpp
// Java bytecode annotation engine. See JvmAnnotate.h for the contract.
//
#include "JvmAnnotate.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <deque>
#include <unordered_map>

namespace ds {

const char* JvmCatName(JvmCat c) {
    switch (c) {
        case JvmCat::None:       return "none";
        case JvmCat::Exit:       return "exit";
        case JvmCat::Input:      return "input";
        case JvmCat::File:       return "file";
        case JvmCat::Network:    return "network";
        case JvmCat::Reflection: return "reflection";
        case JvmCat::ClassLoad:  return "class-load";
        case JvmCat::Native:     return "native/JNI";
        case JvmCat::Crypto:     return "crypto";
        case JvmCat::Exec:       return "process";
        case JvmCat::Thread:     return "thread";
        case JvmCat::Ui:         return "ui";
    }
    return "?";
}

namespace {

std::string lower(std::string s) { for (char& c : s) c = (char)std::tolower((unsigned char)c); return s; }

// The leading "#<idx>" of a CP-operand instruction (invoke*/field/ldc_w/...). 0 = none.
uint16_t cpIndexOf(const Instruction& in) {
    const std::string& o = in.operands;
    size_t h = o.find('#');
    if (h == std::string::npos) return 0;
    unsigned v = 0;
    if (std::sscanf(o.c_str() + h + 1, "%u", &v) != 1) return 0;
    return (uint16_t)v;
}

// Slots for one field-type descriptor starting at s[i]; advances i past it.
// J/D = 2 slots, V = 0, everything else (incl. objects/arrays) = 1.
int fieldTypeSlots(const std::string& s, size_t& i) {
    if (i >= s.size()) return 1;
    char c = s[i];
    if (c == '[') { ++i; return fieldTypeSlots(s, i); }   // array ref = 1 slot
    if (c == 'L') { size_t e = s.find(';', i); i = (e == std::string::npos) ? s.size() : e + 1; return 1; }
    ++i;
    return (c == 'J' || c == 'D') ? 2 : (c == 'V' ? 0 : 1);
}

} // namespace

bool JvmDescriptorSlots(const std::string& d, int& argSlots, int& retSlots) {
    argSlots = retSlots = 0;
    size_t lp = d.find('('), rp = d.find(')');
    if (lp == std::string::npos || rp == std::string::npos || rp < lp) return false;
    size_t i = lp + 1;
    while (i < rp) argSlots += fieldTypeSlots(d, i);
    size_t r = rp + 1;
    retSlots = (r < d.size()) ? fieldTypeSlots(d, r) : 0;
    return true;
}

JvmStackEffect JvmInstrStackEffect(const JvmClassFile& cf, const Instruction& in) {
    const std::string& m = in.mnemonic;
    JvmStackEffect e;
    auto set = [&](int delta, const char* eff) { e.delta = delta; e.effect = eff; };
    auto prefix = [&](const std::string& s) { return m.rfind(s, 0) == 0; };

    // ---- constants / loads (push) ----
    if (m == "aconst_null") { set(+1, "pushes null"); return e; }
    if (prefix("iconst_") || m == "bipush" || m == "sipush") { set(+1, "pushes an int constant"); return e; }
    if (prefix("fconst_")) { set(+1, "pushes a float constant"); return e; }
    if (prefix("lconst_")) { set(+2, "pushes a long constant"); return e; }
    if (prefix("dconst_")) { set(+2, "pushes a double constant"); return e; }
    if (m == "ldc" || m == "ldc_w") {
        const JvmCpEntry* cp = cf.at(cpIndexOf(in));
        const char* what = "a constant";
        if (cp) {
            if (cp->tag == CP_String) what = "the String constant";
            else if (cp->tag == CP_Class) what = "a Class reference";
            else if (cp->tag == CP_Integer) what = "an int constant";
            else if (cp->tag == CP_Float) what = "a float constant";
        }
        e.delta = +1; e.effect = std::string("pushes ") + what + " onto the operand stack"; return e;
    }
    if (m == "ldc2_w") { set(+2, "pushes a long/double constant onto the operand stack"); return e; }
    if (prefix("iload")) { set(+1, "pushes int local variable onto the stack"); return e; }
    if (prefix("fload")) { set(+1, "pushes float local variable onto the stack"); return e; }
    if (prefix("aload") && m != "aaload") { set(+1, "pushes reference local variable onto the stack"); return e; }
    if (prefix("lload")) { set(+2, "pushes long local variable onto the stack"); return e; }
    if (prefix("dload")) { set(+2, "pushes double local variable onto the stack"); return e; }

    // ---- stores (pop into local) ----
    if (prefix("istore")) { set(-1, "pops int into a local variable"); return e; }
    if (prefix("fstore")) { set(-1, "pops float into a local variable"); return e; }
    if (prefix("astore") && m != "aastore") { set(-1, "pops reference into a local variable"); return e; }
    if (prefix("lstore")) { set(-2, "pops long into a local variable"); return e; }
    if (prefix("dstore")) { set(-2, "pops double into a local variable"); return e; }

    // ---- array load/store ----
    if (m == "iaload" || m == "faload" || m == "aaload" || m == "baload" || m == "caload" || m == "saload")
        { set(-1, "loads an array element (pops array+index, pushes value)"); return e; }
    if (m == "laload" || m == "daload") { set(0, "loads a long/double array element"); return e; }
    if (m == "iastore" || m == "fastore" || m == "aastore" || m == "bastore" || m == "castore" || m == "sastore")
        { set(-3, "stores an array element (pops array, index, value)"); return e; }
    if (m == "lastore" || m == "dastore") { set(-4, "stores a long/double array element"); return e; }

    // ---- stack manipulation ----
    if (m == "pop")  { set(-1, "discards the top stack value"); return e; }
    if (m == "pop2") { set(-2, "discards the top two stack slots"); return e; }
    if (m == "dup")  { set(+1, "duplicates the top stack value"); return e; }
    if (m == "dup_x1") { set(+1, "duplicates the top value one slot down"); return e; }
    if (m == "dup_x2") { set(+1, "duplicates the top value two slots down"); return e; }
    if (m == "dup2") { set(+2, "duplicates the top two slots"); return e; }
    if (m == "dup2_x1") { set(+2, "duplicates the top two slots one down"); return e; }
    if (m == "dup2_x2") { set(+2, "duplicates the top two slots two down"); return e; }
    if (m == "swap") { set(0, "swaps the top two stack values"); return e; }

    // ---- arithmetic / logic ----
    if (m == "iadd"||m=="isub"||m=="imul"||m=="idiv"||m=="irem"||m=="iand"||m=="ior"||m=="ixor"||
        m == "ishl"||m=="ishr"||m=="iushr"||m=="fadd"||m=="fsub"||m=="fmul"||m=="fdiv"||m=="frem")
        { set(-1, "binary op (pops two, pushes one)"); return e; }
    if (m == "ladd"||m=="lsub"||m=="lmul"||m=="ldiv"||m=="lrem"||m=="land"||m=="lor"||m=="lxor"||
        m == "dadd"||m=="dsub"||m=="dmul"||m=="ddiv"||m=="drem")
        { set(-2, "long/double binary op (pops two, pushes one)"); return e; }
    if (m == "lshl"||m=="lshr"||m=="lushr") { set(-1, "long shift (pops long+int, pushes long)"); return e; }
    if (m == "ineg"||m=="fneg"||m=="lneg"||m=="dneg") { set(0, "negates the top value"); return e; }
    if (m == "iinc") { set(0, "increments a local variable in place (stack unchanged)"); return e; }

    // ---- conversions ----
    if (m == "i2l"||m=="i2d"||m=="f2l"||m=="f2d") { set(+1, "widening conversion (result is a long/double)"); return e; }
    if (m == "l2i"||m=="l2f"||m=="d2f") { set(-1, "narrowing conversion"); return e; }
    if (m == "i2f"||m=="l2d"||m=="f2i"||m=="d2l"||m=="i2b"||m=="i2c"||m=="i2s") { set(0, "numeric conversion"); return e; }

    // ---- comparisons ----
    if (m == "lcmp") { set(-3, "compares two longs, pushes -1/0/1"); return e; }
    if (m == "fcmpl"||m=="fcmpg") { set(-1, "compares two floats, pushes -1/0/1"); return e; }
    if (m == "dcmpl"||m=="dcmpg") { set(-3, "compares two doubles, pushes -1/0/1"); return e; }

    // ---- branches ----
    if (m == "ifeq"||m=="ifne"||m=="iflt"||m=="ifge"||m=="ifgt"||m=="ifle") { set(-1, "pops one int and branches on the comparison to zero"); return e; }
    if (m == "ifnull"||m=="ifnonnull") { set(-1, "pops a reference and branches on null"); return e; }
    if (prefix("if_icmp")) { set(-2, "pops two ints and branches on the comparison"); return e; }
    if (prefix("if_acmp")) { set(-2, "pops two references and branches on identity"); return e; }
    if (m == "goto"||m=="goto_w") { set(0, "unconditional jump"); return e; }
    if (m == "tableswitch"||m=="lookupswitch") { set(-1, "pops the index and jumps to the matching case"); return e; }
    if (m == "jsr"||m=="jsr_w") { set(+1, "jumps to a subroutine (pushes a return address)"); return e; }
    if (m == "ret") { set(0, "returns from a jsr subroutine"); return e; }

    // ---- returns / throw ----
    if (m == "ireturn"||m=="freturn"||m=="areturn") { e.delta = -1; e.terminator = true; e.effect = "returns the top value to the caller"; return e; }
    if (m == "lreturn"||m=="dreturn") { e.delta = -2; e.terminator = true; e.effect = "returns a long/double to the caller"; return e; }
    if (m == "return") { e.delta = 0; e.terminator = true; e.effect = "returns void"; return e; }
    if (m == "athrow") { e.delta = 0; e.terminator = true; e.effect = "throws the exception on top of the stack"; return e; }

    // ---- field access ----
    if (m == "getstatic" || m == "putstatic" || m == "getfield" || m == "putfield") {
        int slots = 1;
        if (const JvmCpEntry* fr = cf.at(cpIndexOf(in)); fr && fr->tag == CP_Fieldref)
            if (const JvmCpEntry* nt = cf.at(fr->b); nt && nt->tag == CP_NameAndType) {
                std::string t = cf.utf8At(nt->b); size_t z = 0; slots = fieldTypeSlots(t, z);
            }
        if (m == "getstatic") { e.delta = slots; e.effect = "reads a static field onto the stack"; }
        else if (m == "putstatic") { e.delta = -slots; e.effect = "pops the stack into a static field"; }
        else if (m == "getfield") { e.delta = -1 + slots; e.effect = "reads an instance field (pops objectref, pushes the field value)"; }
        else { e.delta = -1 - slots; e.effect = "pops a value and objectref to store an instance field"; }
        return e;
    }

    // ---- invocations ----
    if (m == "invokevirtual" || m == "invokespecial" || m == "invokeinterface" ||
        m == "invokestatic" || m == "invokedynamic") {
        int argSlots = 0, retSlots = 0;
        std::string desc;
        if (const JvmCpEntry* cp = cf.at(cpIndexOf(in))) {
            const JvmCpEntry* nt = nullptr;
            if (cp->tag == CP_Methodref || cp->tag == CP_InterfaceMethodref ||
                cp->tag == CP_Dynamic || cp->tag == CP_InvokeDynamic)
                nt = cf.at(cp->b);
            if (nt && nt->tag == CP_NameAndType) desc = cf.utf8At(nt->b);
        }
        JvmDescriptorSlots(desc, argSlots, retSlots);
        bool hasObjref = (m != "invokestatic" && m != "invokedynamic");
        e.delta = -(argSlots + (hasObjref ? 1 : 0)) + retSlots;
        char buf[160];
        const char* kind = m == "invokestatic" ? "static method"
                         : m == "invokedynamic" ? "dynamic call site"
                         : m == "invokeinterface" ? "interface method"
                         : "instance method";
        if (hasObjref)
            std::snprintf(buf, sizeof(buf),
                          "calls %s using objectref + %d argument slot(s)%s", kind, argSlots,
                          retSlots ? ", pushes the result" : ", returns void");
        else
            std::snprintf(buf, sizeof(buf),
                          "calls %s, consumes %d argument slot(s)%s", kind, argSlots,
                          retSlots ? ", pushes the result" : ", returns void");
        e.effect = buf;
        return e;
    }

    // ---- object / array / misc ----
    if (m == "new") { set(+1, "allocates an object (uninitialized), pushes the reference"); return e; }
    if (m == "newarray"||m=="anewarray") { set(0, "allocates an array (pops length, pushes the array)"); return e; }
    if (m == "arraylength") { set(0, "pops an array, pushes its length"); return e; }
    if (m == "checkcast") { set(0, "checked cast (stack unchanged)"); return e; }
    if (m == "instanceof") { set(0, "pops a reference, pushes 1/0 for the type test"); return e; }
    if (m == "monitorenter"||m=="monitorexit") { set(-1, "pops the lock object (synchronization)"); return e; }
    if (m == "multianewarray") {
        int dims = 0; size_t comma = in.operands.rfind(',');
        if (comma != std::string::npos) dims = std::atoi(in.operands.c_str() + comma + 1);
        e.delta = dims > 0 ? -(dims - 1) : 0;
        e.effect = "allocates a multidimensional array"; return e;
    }
    if (m == "nop") { set(0, ""); return e; }
    // Unknown / db: no model.
    set(0, "");
    return e;
}

std::string JvmBranchMeaning(const Instruction& in) {
    const std::string& m = in.mnemonic;
    char tgt[24];
    std::snprintf(tgt, sizeof(tgt), "0x%llX", (unsigned long long)in.branchTarget);
    auto to = [&](const char* cond) { return std::string("branches to ") + tgt + " if " + cond; };
    if (m == "ifeq") return to("the top int is zero");
    if (m == "ifne") return to("the top int is non-zero");
    if (m == "iflt") return to("the top int < 0");
    if (m == "ifge") return to("the top int >= 0");
    if (m == "ifgt") return to("the top int > 0");
    if (m == "ifle") return to("the top int <= 0");
    if (m == "if_icmpeq") return to("the two ints are equal");
    if (m == "if_icmpne") return to("the two ints differ");
    if (m == "if_icmplt") return to("a < b (the two ints)");
    if (m == "if_icmpge") return to("a >= b (the two ints)");
    if (m == "if_icmpgt") return to("a > b (the two ints)");
    if (m == "if_icmple") return to("a <= b (the two ints)");
    if (m == "if_acmpeq") return to("the two references are the same object");
    if (m == "if_acmpne") return to("the two references differ");
    if (m == "ifnull") return to("the reference is null");
    if (m == "ifnonnull") return to("the reference is non-null");
    if (m == "goto" || m == "goto_w") return std::string("always jumps to ") + tgt;
    if (m == "tableswitch" || m == "lookupswitch") return "jumps to the case matching the popped index (else default)";
    return std::string();
}

// ---- per-method analysis ------------------------------------------------------

namespace {

// Method-name keywords that suggest a validation / gate routine.
bool checkLikeName(const std::string& nameIn) {
    std::string n = lower(nameIn);
    static const char* kw[] = { "check","verify","valid","login","auth","passwd","password",
                                "serial","licen","activat","unlock","correct","secret","authenticate",
                                "compare","matches","verifie","ispremium","isregistered","keygen" };
    for (const char* k : kw) if (n.find(k) != std::string::npos) return true;
    return false;
}

bool isLoopbackLiteral(const std::string& sIn) {
    std::string s = lower(sIn);
    return s.find("localhost") != std::string::npos ||
           s.find("127.0.0.1") != std::string::npos ||
           s.find("[::1]") != std::string::npos ||
           s == "::1";
}

bool isKeepAliveLiteral(const std::string& sIn) {
    std::string s = lower(sIn);
    return s.find("keep-alive") != std::string::npos ||
           s.find("connection: keep") != std::string::npos ||
           s.find("heartbeat") != std::string::npos ||
           s.find("ping") != std::string::npos;
}

bool isAuthHandshakeLiteral(const std::string& sIn) {
    std::string s = lower(sIn);
    return s.find("authorization") != std::string::npos ||
           s.find("bearer") != std::string::npos ||
           s.find("token") != std::string::npos ||
           s.find("session") != std::string::npos ||
           s.find("signature") != std::string::npos ||
           s.find("sign=") != std::string::npos ||
           s.find("key=") != std::string::npos ||
           s.find("apikey") != std::string::npos ||
           s.find("api_key") != std::string::npos;
}

// Map an invoke target (owner + name) to a high-level category + finding text.
// Returns JvmCat::None when nothing notable.
JvmCat categorizeCall(const std::string& owner, const std::string& name, std::string& text) {
    std::string o = lower(owner), n = lower(name);
    auto ohas = [&](const char* k) { return o.find(k) != std::string::npos; };
    auto nis  = [&](const char* k) { return n == k; };

    if (ohas("java/lang/system") && nis("exit")) { text = "System.exit (terminates the JVM)"; return JvmCat::Exit; }
    if (ohas("java/lang/runtime") && (nis("exit") || nis("halt"))) { text = "Runtime.exit/halt"; return JvmCat::Exit; }

    if (ohas("java/util/scanner") || (ohas("java/io/bufferedreader") && (nis("readline"))) ||
        (ohas("java/io/console") && (nis("readline") || nis("readpassword"))) ||
        nis("nextline") || nis("nextint") || (ohas("java/io/datainputstream") && nis("readutf"))) {
        text = "reads user input (" + name + ")"; return JvmCat::Input;
    }
    if (ohas("java/io/file") || ohas("java/nio/file") || ohas("java/io/fileinputstream") ||
        ohas("java/io/filereader") || ohas("java/io/fileoutputstream") || ohas("java/io/randomaccessfile")) {
        text = "file I/O (" + JvmShortClassName(owner) + "." + name + ")"; return JvmCat::File;
    }
    if (ohas("java/net/socket") || ohas("java/net/url") || ohas("java/net/http") ||
        ohas("httpurlconnection") || ohas("java/net/serversocket") || ohas("java/net/inetaddress")) {
        text = "network I/O (" + JvmShortClassName(owner) + "." + name + ")"; return JvmCat::Network;
    }
    if (ohas("java/lang/reflect") || (ohas("java/lang/class") && (nis("forname") || nis("getmethod") ||
        nis("getdeclaredmethod") || nis("getdeclaredfield") || nis("getfield"))) ||
        (n == "invoke" && ohas("method")) || nis("setaccessible")) {
        text = "reflection (" + JvmShortClassName(owner) + "." + name + ")"; return JvmCat::Reflection;
    }
    if (ohas("classloader") || nis("defineclass") || nis("loadclass")) {
        text = "class loading (" + JvmShortClassName(owner) + "." + name + ")"; return JvmCat::ClassLoad;
    }
    if ((ohas("java/lang/system") || ohas("java/lang/runtime")) && (nis("load") || nis("loadlibrary"))) {
        text = "loads a native library (JNI)"; return JvmCat::Native;
    }
    if (ohas("java/lang/runtime") && nis("exec")) { text = "Runtime.exec (spawns a process)"; return JvmCat::Exec; }
    if (ohas("java/lang/processbuilder")) { text = "ProcessBuilder (spawns a process)"; return JvmCat::Exec; }
    if (ohas("java/security/messagedigest") || ohas("javax/crypto") || ohas("java/security/signature") ||
        ohas("java/util/base64")) {
        text = "crypto/encoding (" + JvmShortClassName(owner) + "." + name + ")"; return JvmCat::Crypto;
    }
    if (ohas("java/lang/thread") || ohas("java/util/concurrent")) {
        text = "threading (" + JvmShortClassName(owner) + "." + name + ")"; return JvmCat::Thread;
    }
    if (ohas("javax/swing") || ohas("java/awt") || ohas("javafx")) {
        text = "UI toolkit (" + JvmShortClassName(owner) + "." + name + ")"; return JvmCat::Ui;
    }
    return JvmCat::None;
}

} // namespace

JvmMethodAnalysis AnalyzeJvmMethod(const JvmClassFile& cf, const JvmMethod& m,
                                   const std::vector<Instruction>& insns) {
    JvmMethodAnalysis a;
    a.name = m.name; a.descriptor = m.descriptor;
    a.pretty = JvmPrettyMethod(m.name, m.descriptor);
    a.accessFlags = m.accessFlags;
    a.isStatic   = (m.accessFlags & JVM_ACC_STATIC) != 0;
    a.isNative   = (m.accessFlags & JVM_ACC_NATIVE) != 0;
    a.isAbstract = (m.accessFlags & JVM_ACC_ABSTRACT) != 0;
    a.declaredMaxStack = m.maxStack;
    a.maxLocals = m.maxLocals;
    a.notes.resize(insns.size());

    // Index bci -> instruction position for the abstract-interpretation worklist.
    std::unordered_map<uint64_t, int> idxOf;
    for (int i = 0; i < (int)insns.size(); ++i) idxOf[insns[i].address] = i;

    // Precompute deltas + effects.
    std::vector<JvmStackEffect> eff(insns.size());
    for (size_t i = 0; i < insns.size(); ++i) eff[i] = JvmInstrStackEffect(cf, insns[i]);

    // Abstract interpretation: depth on entry to each instruction. Seed bci 0 = 0
    // and every exception-handler start = 1 (the thrown exception object).
    std::vector<int> depthIn(insns.size(), -1);
    std::deque<int> work;
    auto seed = [&](uint64_t bci, int d) {
        auto it = idxOf.find(bci);
        if (it == idxOf.end()) return;
        int idx = it->second;
        if (depthIn[idx] == -1) { depthIn[idx] = d; work.push_back(idx); }
        else if (depthIn[idx] != d) a.stackConsistent = false;   // merge mismatch
    };
    if (!insns.empty()) seed(insns.front().address, 0);
    for (const JvmExceptionHandler& h : m.handlers) seed(m.codeOffset + h.handlerPC, 1);

    while (!work.empty()) {
        int i = work.front(); work.pop_front();
        int d = depthIn[i];
        const Instruction& in = insns[i];
        const JvmStackEffect& E = eff[i];
        int after = d + E.delta;
        if (after < 0) { a.stackConsistent = false; after = 0; }   // underflow (obfuscation?)
        // Successors: fallthrough (unless terminator or unconditional goto),
        // branch target, and switch cases.
        bool uncond = (in.mnemonic == "goto" || in.mnemonic == "goto_w" ||
                       in.mnemonic == "tableswitch" || in.mnemonic == "lookupswitch");
        if (!E.terminator && !uncond && i + 1 < (int)insns.size())
            seed(insns[i + 1].address, after);
        if (HasBranchTarget(in) && in.mnemonic != "ret") {
            // For switch the popped value is gone before the jump: targets see `after`.
            seed(in.branchTarget, after);
        }
        for (uint64_t t : in.extraTargets) seed(t, after);
    }

    // Fill notes + collect calls/fields/strings + per-instruction findings.
    for (size_t i = 0; i < insns.size(); ++i) {
        const Instruction& in = insns[i];
        JvmInsnNote& nt = a.notes[i];
        nt.bci = in.address;
        nt.stackBefore = depthIn[i];
        nt.stackAfter  = (depthIn[i] >= 0 && !eff[i].terminator) ? depthIn[i] + eff[i].delta : -1;
        if (nt.stackAfter < 0 && depthIn[i] >= 0 && eff[i].terminator) nt.stackAfter = -1;
        nt.effect = eff[i].effect;
        nt.branch = JvmBranchMeaning(in);
        int peak = std::max(nt.stackBefore, nt.stackAfter);
        if (peak > a.computedMaxStack) a.computedMaxStack = peak;

        const std::string& mn = in.mnemonic;
        // ldc/ldc_w String constant.
        if (mn == "ldc" || mn == "ldc_w") {
            if (const JvmCpEntry* cp = cf.at(cpIndexOf(in)); cp && cp->tag == CP_String)
                a.strings.push_back({ in.address, cf.utf8At(cp->a) });
        }
        // field access.
        if (mn == "getstatic" || mn == "putstatic" || mn == "getfield" || mn == "putfield") {
            JvmFieldAccess fa; fa.bci = in.address;
            fa.put = (mn[0] == 'p'); fa.isStatic = (mn.find("static") != std::string::npos);
            if (const JvmCpEntry* fr = cf.at(cpIndexOf(in)); fr && fr->tag == CP_Fieldref) {
                fa.owner = cf.classNameAt(fr->a);
                if (const JvmCpEntry* ntp = cf.at(fr->b); ntp && ntp->tag == CP_NameAndType) {
                    fa.name = cf.utf8At(ntp->a); fa.type = cf.utf8At(ntp->b);
                }
            }
            a.fields.push_back(std::move(fa));
        }
        // invoke* edges + category findings.
        if (in.isCall) {
            JvmCall c; c.bci = in.address; c.local = HasBranchTarget(in);
            c.kind = mn == "invokestatic" ? "static" : mn == "invokespecial" ? "special"
                   : mn == "invokeinterface" ? "interface" : mn == "invokedynamic" ? "dynamic" : "virtual";
            if (const JvmCpEntry* cp = cf.at(cpIndexOf(in))) {
                if (cp->tag == CP_Methodref || cp->tag == CP_InterfaceMethodref) c.owner = cf.classNameAt(cp->a);
                if (const JvmCpEntry* ntp = cf.at(cp->b); ntp && ntp->tag == CP_NameAndType) {
                    c.name = cf.utf8At(ntp->a); c.descriptor = cf.utf8At(ntp->b);
                }
            }
            JvmDescriptorSlots(c.descriptor, c.argSlots, c.retSlots);
            std::string catText;
            JvmCat cat = categorizeCall(c.owner, c.name, catText);
            if (cat != JvmCat::None) {
                JvmFinding f; f.cat = cat; f.text = catText; f.bci = in.address; f.confidence = 0.7f;
                f.evidence = c.kind + " call to " + (c.owner.empty() ? c.name : c.owner + "." + c.name) +
                             " at bci " + std::to_string(in.address - m.codeOffset);
                a.findings.push_back(std::move(f));
            }
            a.calls.push_back(std::move(c));
        }
    }

    // Localhost crackme/control-channel shape: JVM code that combines network APIs
    // with loopback URLs/ports, keep-alive/heartbeat strings, or auth/signature keys.
    // These are still hints, not facts: the UI shows confidence + evidence.
    {
        bool hasNetworkCall = false, hasLoopback = false, hasKeepAlive = false, hasAuth = false;
        uint64_t evidenceBci = m.codeOffset;
        std::string ev;
        for (const JvmFinding& f : a.findings)
            if (f.cat == JvmCat::Network) { hasNetworkCall = true; evidenceBci = f.bci; break; }
        for (const JvmStringRef& s : a.strings) {
            if (isLoopbackLiteral(s.text)) {
                hasLoopback = true; evidenceBci = s.bci;
                if (!ev.empty()) ev += "; ";
                ev += "loopback string \"" + s.text + "\"";
            }
            if (isKeepAliveLiteral(s.text)) {
                hasKeepAlive = true;
                if (!ev.empty()) ev += "; ";
                ev += "keep-alive/heartbeat string \"" + s.text + "\"";
            }
            if (isAuthHandshakeLiteral(s.text)) {
                hasAuth = true;
                if (!ev.empty()) ev += "; ";
                ev += "auth/signature string \"" + s.text + "\"";
            }
        }
        if (hasNetworkCall && hasLoopback) {
            float conf = 0.78f + (hasKeepAlive ? 0.08f : 0.0f) + (hasAuth ? 0.08f : 0.0f);
            if (conf > 0.94f) conf = 0.94f;
            JvmFinding f;
            f.cat = JvmCat::Network;
            f.text = hasKeepAlive || hasAuth
                   ? "looks like a localhost auth / keep-alive handshake"
                   : "uses a localhost / loopback network endpoint";
            f.evidence = "method has java.net call(s); " + ev;
            f.confidence = conf;
            f.bci = evidenceBci;
            a.findings.push_back(std::move(f));
        } else if (hasLoopback || hasKeepAlive || hasAuth) {
            JvmFinding f;
            f.cat = JvmCat::Network;
            f.text = "network/auth-related string constant";
            f.evidence = ev.empty() ? "string constant suggests local network/auth flow" : ev;
            f.confidence = hasLoopback ? 0.62f : 0.55f;
            f.bci = evidenceBci;
            a.findings.push_back(std::move(f));
        }
    }

    // ---- check-method scoring ----
    {
        float score = 0.0f; std::string ev;
        auto add = [&](float w, const std::string& why) { score += w; if (!ev.empty()) ev += "; "; ev += why; };
        int argA = 0, retA = 0; JvmDescriptorSlots(m.descriptor, argA, retA);
        bool returnsBool = false;
        { size_t rp = m.descriptor.find(')'); if (rp != std::string::npos && rp + 1 < m.descriptor.size()) returnsBool = m.descriptor[rp + 1] == 'Z'; }
        if (checkLikeName(m.name)) add(0.4f, "method name suggests a validation routine");
        if (returnsBool)          add(0.2f, "returns boolean");
        bool takesString = m.descriptor.find("Ljava/lang/String;") != std::string::npos;
        if (takesString && checkLikeName(m.name)) add(0.1f, "takes a String argument");
        for (const JvmCall& c : a.calls) {
            std::string n = lower(c.name);
            if ((c.owner.find("String") != std::string::npos || c.owner.find("string") != std::string::npos) &&
                (n == "equals" || n == "equalsignorecase" || n == "compareto" || n == "contentequals")) {
                add(0.3f, "compares strings with String." + c.name); break;
            }
        }
        for (const JvmCall& c : a.calls) {
            if (c.owner.find("MessageDigest") != std::string::npos || c.owner.find("Mac") != std::string::npos) {
                add(0.2f, "hashes/MACs a value (" + JvmShortClassName(c.owner) + ")"); break;
            }
        }
        for (const JvmCall& c : a.calls)
            if (lower(c.name) == "exit" && (c.owner.find("System") != std::string::npos)) { add(0.1f, "calls System.exit on a failure path"); break; }
        if (!a.strings.empty() && checkLikeName(m.name)) add(0.1f, std::to_string(a.strings.size()) + " embedded string constant(s)");
        bool localAuth = false;
        for (const JvmFinding& f : a.findings)
            if (f.cat == JvmCat::Network && f.text.find("localhost auth") != std::string::npos) { localAuth = true; break; }
        if (localAuth) add(0.2f, "network handoff uses localhost/auth/keep-alive evidence");
        if (score > 1.0f) score = 1.0f;
        a.checkConfidence = score;
        a.checkEvidence = ev;
        a.likelyCheck = score >= 0.5f;
        if (a.likelyCheck) {
            JvmFinding f; f.cat = JvmCat::None; f.confidence = score; f.bci = m.codeOffset;
            f.text = "looks like a validation / check method"; f.evidence = ev;
            a.findings.push_back(std::move(f));
        }
    }

    // ---- summary line ----
    {
        std::string s;
        if (a.isStatic) s += "static ";
        if (a.isNative) s += "native ";
        s += "stack " + std::to_string(a.computedMaxStack);
        if (a.declaredMaxStack && (int)a.declaredMaxStack != a.computedMaxStack)
            s += "/" + std::to_string(a.declaredMaxStack);
        if (!a.stackConsistent) s += " (irregular!)";
        if (!a.calls.empty())   s += " · " + std::to_string(a.calls.size()) + " call(s)";
        if (!a.strings.empty()) s += " · " + std::to_string(a.strings.size()) + " string(s)";
        // Distinct categories.
        std::vector<const char*> cats;
        for (const JvmFinding& f : a.findings)
            if (f.cat != JvmCat::None) {
                const char* nm = JvmCatName(f.cat);
                if (std::find(cats.begin(), cats.end(), nm) == cats.end()) cats.push_back(nm);
            }
        for (const char* c : cats) s += std::string(" · ") + c;
        if (a.likelyCheck) s += " · CHECK?";
        a.summary = s;
    }
    return a;
}

} // namespace ds
