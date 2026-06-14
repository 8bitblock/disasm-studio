#include "JvmDisassembler.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace ds {

// ---- opcode table -------------------------------------------------------------
// Operand encodings (JVMS 6.5). Fixed lengths except the two switches and the
// `wide` prefix, which are handled out-of-line.
enum OpKind : uint8_t {
    K0,        // no operands
    KU1,       // u1 local-variable index (wide-able)
    KS1,       // s1 immediate (bipush)
    KS2,       // s2 immediate (sipush)
    KCP1,      // u1 constant-pool index (ldc)
    KCP2,      // u2 constant-pool index
    KIINC,     // u1 index, s1 const (wide: u2, s2)
    KBR2,      // s2 branch offset
    KBR4,      // s4 branch offset (goto_w / jsr_w)
    KNEWARR,   // u1 primitive array type
    KIFACE,    // u2 cp index, u1 count, u1 zero (invokeinterface)
    KIDYN,     // u2 cp index, u2 zero (invokedynamic)
    KMULTI,    // u2 cp index, u1 dimensions
    KTBL,      // tableswitch (variable)
    KLKP,      // lookupswitch (variable)
    KWIDE,     // wide prefix
    KBAD,      // unassigned opcode
};

struct OpInfo { const char* name; uint8_t kind; };

static const OpInfo kOps[256] = {
    /*0x00*/ {"nop",K0},          {"aconst_null",K0}, {"iconst_m1",K0},  {"iconst_0",K0},
    /*0x04*/ {"iconst_1",K0},     {"iconst_2",K0},    {"iconst_3",K0},   {"iconst_4",K0},
    /*0x08*/ {"iconst_5",K0},     {"lconst_0",K0},    {"lconst_1",K0},   {"fconst_0",K0},
    /*0x0c*/ {"fconst_1",K0},     {"fconst_2",K0},    {"dconst_0",K0},   {"dconst_1",K0},
    /*0x10*/ {"bipush",KS1},      {"sipush",KS2},     {"ldc",KCP1},      {"ldc_w",KCP2},
    /*0x14*/ {"ldc2_w",KCP2},     {"iload",KU1},      {"lload",KU1},     {"fload",KU1},
    /*0x18*/ {"dload",KU1},       {"aload",KU1},      {"iload_0",K0},    {"iload_1",K0},
    /*0x1c*/ {"iload_2",K0},      {"iload_3",K0},     {"lload_0",K0},    {"lload_1",K0},
    /*0x20*/ {"lload_2",K0},      {"lload_3",K0},     {"fload_0",K0},    {"fload_1",K0},
    /*0x24*/ {"fload_2",K0},      {"fload_3",K0},     {"dload_0",K0},    {"dload_1",K0},
    /*0x28*/ {"dload_2",K0},      {"dload_3",K0},     {"aload_0",K0},    {"aload_1",K0},
    /*0x2c*/ {"aload_2",K0},      {"aload_3",K0},     {"iaload",K0},     {"laload",K0},
    /*0x30*/ {"faload",K0},       {"daload",K0},      {"aaload",K0},     {"baload",K0},
    /*0x34*/ {"caload",K0},       {"saload",K0},      {"istore",KU1},    {"lstore",KU1},
    /*0x38*/ {"fstore",KU1},      {"dstore",KU1},     {"astore",KU1},    {"istore_0",K0},
    /*0x3c*/ {"istore_1",K0},     {"istore_2",K0},    {"istore_3",K0},   {"lstore_0",K0},
    /*0x40*/ {"lstore_1",K0},     {"lstore_2",K0},    {"lstore_3",K0},   {"fstore_0",K0},
    /*0x44*/ {"fstore_1",K0},     {"fstore_2",K0},    {"fstore_3",K0},   {"dstore_0",K0},
    /*0x48*/ {"dstore_1",K0},     {"dstore_2",K0},    {"dstore_3",K0},   {"astore_0",K0},
    /*0x4c*/ {"astore_1",K0},     {"astore_2",K0},    {"astore_3",K0},   {"iastore",K0},
    /*0x50*/ {"lastore",K0},      {"fastore",K0},     {"dastore",K0},    {"aastore",K0},
    /*0x54*/ {"bastore",K0},      {"castore",K0},     {"sastore",K0},    {"pop",K0},
    /*0x58*/ {"pop2",K0},         {"dup",K0},         {"dup_x1",K0},     {"dup_x2",K0},
    /*0x5c*/ {"dup2",K0},         {"dup2_x1",K0},     {"dup2_x2",K0},    {"swap",K0},
    /*0x60*/ {"iadd",K0},         {"ladd",K0},        {"fadd",K0},       {"dadd",K0},
    /*0x64*/ {"isub",K0},         {"lsub",K0},        {"fsub",K0},       {"dsub",K0},
    /*0x68*/ {"imul",K0},         {"lmul",K0},        {"fmul",K0},       {"dmul",K0},
    /*0x6c*/ {"idiv",K0},         {"ldiv",K0},        {"fdiv",K0},       {"ddiv",K0},
    /*0x70*/ {"irem",K0},         {"lrem",K0},        {"frem",K0},       {"drem",K0},
    /*0x74*/ {"ineg",K0},         {"lneg",K0},        {"fneg",K0},       {"dneg",K0},
    /*0x78*/ {"ishl",K0},         {"lshl",K0},        {"ishr",K0},       {"lshr",K0},
    /*0x7c*/ {"iushr",K0},        {"lushr",K0},       {"iand",K0},       {"land",K0},
    /*0x80*/ {"ior",K0},          {"lor",K0},         {"ixor",K0},       {"lxor",K0},
    /*0x84*/ {"iinc",KIINC},      {"i2l",K0},         {"i2f",K0},        {"i2d",K0},
    /*0x88*/ {"l2i",K0},          {"l2f",K0},         {"l2d",K0},        {"f2i",K0},
    /*0x8c*/ {"f2l",K0},          {"f2d",K0},         {"d2i",K0},        {"d2l",K0},
    /*0x90*/ {"d2f",K0},          {"i2b",K0},         {"i2c",K0},        {"i2s",K0},
    /*0x94*/ {"lcmp",K0},         {"fcmpl",K0},       {"fcmpg",K0},      {"dcmpl",K0},
    /*0x98*/ {"dcmpg",K0},        {"ifeq",KBR2},      {"ifne",KBR2},     {"iflt",KBR2},
    /*0x9c*/ {"ifge",KBR2},       {"ifgt",KBR2},      {"ifle",KBR2},     {"if_icmpeq",KBR2},
    /*0xa0*/ {"if_icmpne",KBR2},  {"if_icmplt",KBR2}, {"if_icmpge",KBR2},{"if_icmpgt",KBR2},
    /*0xa4*/ {"if_icmple",KBR2},  {"if_acmpeq",KBR2}, {"if_acmpne",KBR2},{"goto",KBR2},
    /*0xa8*/ {"jsr",KBR2},        {"ret",KU1},        {"tableswitch",KTBL},{"lookupswitch",KLKP},
    /*0xac*/ {"ireturn",K0},      {"lreturn",K0},     {"freturn",K0},    {"dreturn",K0},
    /*0xb0*/ {"areturn",K0},      {"return",K0},      {"getstatic",KCP2},{"putstatic",KCP2},
    /*0xb4*/ {"getfield",KCP2},   {"putfield",KCP2},  {"invokevirtual",KCP2},{"invokespecial",KCP2},
    /*0xb8*/ {"invokestatic",KCP2},{"invokeinterface",KIFACE},{"invokedynamic",KIDYN},{"new",KCP2},
    /*0xbc*/ {"newarray",KNEWARR},{"anewarray",KCP2}, {"arraylength",K0},{"athrow",K0},
    /*0xc0*/ {"checkcast",KCP2},  {"instanceof",KCP2},{"monitorenter",K0},{"monitorexit",K0},
    /*0xc4*/ {"wide",KWIDE},      {"multianewarray",KMULTI},{"ifnull",KBR2},{"ifnonnull",KBR2},
    /*0xc8*/ {"goto_w",KBR4},     {"jsr_w",KBR4},     {"breakpoint",K0}, {nullptr,KBAD},
    /*0xcc*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xd0*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xd4*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xd8*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xdc*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xe0*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xe4*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xe8*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xec*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xf0*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xf4*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xf8*/ {nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},{nullptr,KBAD},
    /*0xfc*/ {nullptr,KBAD},{nullptr,KBAD},{"impdep1",K0},{"impdep2",K0},
};

// Primitive type codes for newarray (JVMS table 6.5.newarray-A).
static const char* newarrayType(uint8_t t) {
    switch (t) {
        case 4: return "boolean"; case 5: return "char";  case 6: return "float";
        case 7: return "double";  case 8: return "byte";  case 9: return "short";
        case 10: return "int";    case 11: return "long";
    }
    return "?";
}

static void appendHexBytes(std::string& out, const uint8_t* p, size_t n) {
    char b[4];
    for (size_t i = 0; i < n; ++i) {
        std::snprintf(b, sizeof(b), "%02X", p[i]);
        if (!out.empty()) out.push_back(' ');
        out += b;
    }
}

static int16_t rdS2(const uint8_t* p)  { return (int16_t)((p[0] << 8) | p[1]); }
static uint16_t rdU2(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
static int32_t rdS4(const uint8_t* p) {
    return (int32_t)(((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                     ((uint32_t)p[2] << 8) | p[3]);
}

void AttachJvmClass(IDisassembler& dis, std::shared_ptr<const JvmClassFile> cf) {
    if (auto* j = dynamic_cast<JvmDisassembler*>(&dis))
        j->attachClass(std::move(cf));
}

void JvmDisassembler::attachClass(std::shared_ptr<const JvmClassFile> cf) {
    class_ = std::move(cf);
    localMethodOff_.clear();
    if (!class_ || !class_->ok) return;
    for (const auto& m : class_->methods)
        if (m.codeLength)
            localMethodOff_[m.name + ":" + m.descriptor] = m.codeOffset;
}

uint32_t JvmDisassembler::bciFor(uint64_t va) const {
    if (class_ && class_->ok)
        if (const JvmMethod* m = class_->methodAtOffset(va))
            return (uint32_t)(va - m->codeOffset);
    return (uint32_t)va;   // identity mapping fallback (va == file offset)
}

bool JvmDisassembler::decodeOne(const uint8_t* data, size_t size,
                                uint64_t virtualAddress, Instruction& out) {
    return decodeAt(data, size, virtualAddress, bciFor(virtualAddress), out);
}

std::vector<Instruction> JvmDisassembler::disassemble(const uint8_t* data, size_t size,
                                                      uint64_t virtualAddress,
                                                      size_t maxInstructions) {
    std::vector<Instruction> out;
    if (!data) return out;
    size_t off = 0;
    // Without a class context, assume the window starts at a code-array start
    // (true for the per-method sections the JavaClass loader maps), so the
    // switch-padding bci is the offset into the window.
    const bool haveClass = class_ && class_->ok;
    while (off < size && (!maxInstructions || out.size() < maxInstructions)) {
        const uint64_t va = virtualAddress + off;
        const uint32_t bci = haveClass ? bciFor(va) : (uint32_t)off;
        Instruction in;
        if (!decodeAt(data + off, size - off, va, bci, in)) {
            // Undecodable byte: emit a `db`-style row and resync one byte on,
            // mirroring the x86 backends' behaviour.
            in = Instruction{};
            in.address = va;
            in.length  = 1;
            appendHexBytes(in.bytes, data + off, 1);
            in.mnemonic = "db";
            char b[8]; std::snprintf(b, sizeof(b), "0x%02X", data[off]);
            in.operands = b;
        }
        out.push_back(std::move(in));
        off += out.back().length;
    }
    return out;
}

bool JvmDisassembler::decodeAt(const uint8_t* d, size_t n, uint64_t va, uint32_t bci,
                               Instruction& out) const {
    if (!d || n < 1) return false;
    const uint8_t op = d[0];
    const OpInfo& info = kOps[op];
    if (info.kind == KBAD) return false;

    out = Instruction{};
    out.address  = va;
    out.mnemonic = info.name;

    char buf[96];
    size_t len = 1;
    const JvmClassFile* cf = (class_ && class_->ok) ? class_.get() : nullptr;

    // Resolve a constant-pool operand: "#n" text + readable comment, and for
    // method refs into THIS class, the local code VA as the branch target.
    auto cpOperand = [&](uint16_t idx, bool wantLocalTarget) {
        std::snprintf(buf, sizeof(buf), "#%u", idx);
        out.operands = buf;
        if (!cf) return;
        out.comment = cf->describeCp(idx);
        if (!wantLocalTarget) return;
        const JvmCpEntry* e = cf->at(idx);
        if (!e || (e->tag != CP_Methodref && e->tag != CP_InterfaceMethodref)) return;
        if (cf->classNameAt(e->a) != cf->thisClass) return;
        if (const JvmCpEntry* nt = cf->at(e->b); nt && nt->tag == CP_NameAndType) {
            auto it = localMethodOff_.find(cf->utf8At(nt->a) + ":" + cf->utf8At(nt->b));
            if (it != localMethodOff_.end()) out.branchTarget = it->second;
        }
    };

    switch (info.kind) {
        case K0: break;
        case KU1: {
            if (n < 2) return false;
            len = 2;
            std::snprintf(buf, sizeof(buf), "%u", d[1]);
            out.operands = buf;
            break;
        }
        case KS1: {
            if (n < 2) return false;
            len = 2;
            std::snprintf(buf, sizeof(buf), "%d", (int8_t)d[1]);
            out.operands = buf;
            break;
        }
        case KS2: {
            if (n < 3) return false;
            len = 3;
            std::snprintf(buf, sizeof(buf), "%d", rdS2(d + 1));
            out.operands = buf;
            break;
        }
        case KCP1: {
            if (n < 2) return false;
            len = 2;
            cpOperand(d[1], false);
            break;
        }
        case KCP2: {
            if (n < 3) return false;
            len = 3;
            cpOperand(rdU2(d + 1), op >= 0xB6 && op <= 0xB8);  // invokevirtual/special/static
            break;
        }
        case KIINC: {
            if (n < 3) return false;
            len = 3;
            std::snprintf(buf, sizeof(buf), "%u, %d", d[1], (int8_t)d[2]);
            out.operands = buf;
            break;
        }
        case KBR2: case KBR4: {
            const size_t w = (info.kind == KBR2) ? 2 : 4;
            if (n < 1 + w) return false;
            len = 1 + w;
            const int32_t rel = (w == 2) ? rdS2(d + 1) : rdS4(d + 1);
            const int64_t tgt = (int64_t)va + rel;
            if (tgt < 0) return false;
            out.branchTarget = (uint64_t)tgt;
            std::snprintf(buf, sizeof(buf), "0x%llX", (unsigned long long)out.branchTarget);
            out.operands = buf;
            break;
        }
        case KNEWARR: {
            if (n < 2) return false;
            len = 2;
            out.operands = newarrayType(d[1]);
            break;
        }
        case KIFACE: {
            if (n < 5) return false;
            len = 5;
            const uint16_t idx = rdU2(d + 1);
            cpOperand(idx, false);
            std::snprintf(buf, sizeof(buf), "#%u, %u", idx, d[3]);
            out.operands = buf;
            break;
        }
        case KIDYN: {
            if (n < 5) return false;
            len = 5;
            cpOperand(rdU2(d + 1), false);
            break;
        }
        case KMULTI: {
            if (n < 4) return false;
            len = 4;
            const uint16_t idx = rdU2(d + 1);
            cpOperand(idx, false);
            std::snprintf(buf, sizeof(buf), "#%u, %u", idx, d[3]);
            out.operands = buf;
            break;
        }
        case KTBL: {
            // pad to a 4-byte boundary relative to the code-array start
            const size_t pad = (size_t)((~bci) & 3u);          // ((bci+1)+pad) % 4 == 0
            if (n < 1 + pad + 12) return false;
            const uint8_t* q = d + 1 + pad;
            const int32_t def = rdS4(q), low = rdS4(q + 4), high = rdS4(q + 8);
            if (high < low) return false;
            const uint64_t count = (uint64_t)high - (uint64_t)low + 1;
            if (count > (n - 1 - pad - 12) / 4) return false;  // table must fit the buffer
            len = 1 + pad + 12 + (size_t)count * 4;
            out.branchTarget = va + def;
            std::snprintf(buf, sizeof(buf), "%d..%d, default=0x%llX",
                          low, high, (unsigned long long)out.branchTarget);
            out.operands = buf;
            out.extraTargets.reserve((size_t)count);
            std::string cases;
            for (uint64_t k = 0; k < count; ++k) {
                const uint64_t t = va + rdS4(q + 12 + k * 4);
                out.extraTargets.push_back(t);
                if (k < 4) {
                    std::snprintf(buf, sizeof(buf), "%s%lld -> 0x%llX",
                                  cases.empty() ? "" : ", ",
                                  (long long)(low + (int64_t)k), (unsigned long long)t);
                    cases += buf;
                }
            }
            if (count > 4) cases += ", ...";
            out.comment = cases;
            break;
        }
        case KLKP: {
            const size_t pad = (size_t)((~bci) & 3u);
            if (n < 1 + pad + 8) return false;
            const uint8_t* q = d + 1 + pad;
            const int32_t def = rdS4(q), npairs = rdS4(q + 4);
            if (npairs < 0) return false;
            if ((uint64_t)npairs > (n - 1 - pad - 8) / 8) return false;
            len = 1 + pad + 8 + (size_t)npairs * 8;
            out.branchTarget = va + def;
            std::snprintf(buf, sizeof(buf), "%d pairs, default=0x%llX",
                          npairs, (unsigned long long)out.branchTarget);
            out.operands = buf;
            out.extraTargets.reserve((size_t)npairs);
            std::string cases;
            for (int32_t k = 0; k < npairs; ++k) {
                const int32_t match = rdS4(q + 8 + (size_t)k * 8);
                const uint64_t t = va + rdS4(q + 12 + (size_t)k * 8);
                out.extraTargets.push_back(t);
                if (k < 4) {
                    std::snprintf(buf, sizeof(buf), "%s%d -> 0x%llX",
                                  cases.empty() ? "" : ", ", match, (unsigned long long)t);
                    cases += buf;
                }
            }
            if (npairs > 4) cases += ", ...";
            out.comment = cases;
            break;
        }
        case KWIDE: {
            if (n < 2) return false;
            const uint8_t sub = d[1];
            if (sub == 0x84) {                                  // wide iinc: u2 index, s2 const
                if (n < 6) return false;
                len = 6;
                out.mnemonic = "iinc";
                std::snprintf(buf, sizeof(buf), "%u, %d", rdU2(d + 2), rdS2(d + 4));
                out.operands = buf;
            } else if (kOps[sub].kind == KU1) {                 // wide *load/*store/ret: u2 index
                if (n < 4) return false;
                len = 4;
                out.mnemonic = kOps[sub].name;
                std::snprintf(buf, sizeof(buf), "%u", rdU2(d + 2));
                out.operands = buf;
            } else {
                return false;
            }
            break;
        }
        case KBAD: return false;
    }

    out.length = (uint32_t)len;
    appendHexBytes(out.bytes, d, std::min(len, n));

    // Control-flow classification (CFG / FunctionAnalyzer / navigation):
    //   invoke*           -> call (falls through; local target when resolvable)
    //   *return / athrow  -> return-like terminator (no fallthrough)
    //   goto/goto_w, switches -> unconditional transfers
    //   if* / jsr         -> conditional-style (fallthrough edge kept; jsr's
    //                        subroutine returns to the next instruction)
    //   ret (0xa9)        -> indirect terminator (jsr return)
    if (op >= 0xB6 && op <= 0xBA) {                             // invokevirtual..invokedynamic
        out.isCall = out.isBranch = true;
    } else if ((op >= 0xAC && op <= 0xB1) || op == 0xBF) {      // ireturn..return, athrow
        out.isRet = out.isBranch = true;
    } else if (op == 0xA9 || (op == 0xC4 && d[1] == 0xA9)) {    // ret / wide ret
        out.isRet = out.isBranch = true;
    } else if ((op >= 0x99 && op <= 0xA8) || op == 0xC6 || op == 0xC7 ||
               op == 0xC8 || op == 0xC9 || op == 0xAA || op == 0xAB) {
        out.isBranch = true;                                    // ifs, goto(_w), jsr(_w), switches
    }
    return true;
}

} // namespace ds
