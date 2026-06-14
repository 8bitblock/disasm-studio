#include "JvmClass.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace ds {

// ---- bounded big-endian cursor ----------------------------------------------
// Every multi-byte field in a class file is big-endian (JVMS 4.1). The cursor
// latches `fail` on the first out-of-bounds read; callers check it once per
// structure instead of per field.
namespace {
struct Cur {
    const uint8_t* p = nullptr;
    size_t n = 0, off = 0;
    bool fail = false;

    bool need(size_t k) {
        if (fail || off > n || n - off < k) { fail = true; return false; }
        return true;
    }
    uint8_t u1() { if (!need(1)) return 0; return p[off++]; }
    uint16_t u2() {
        if (!need(2)) return 0;
        uint16_t v = (uint16_t)((p[off] << 8) | p[off + 1]); off += 2; return v;
    }
    uint32_t u4() {
        if (!need(4)) return 0;
        uint32_t v = ((uint32_t)p[off] << 24) | ((uint32_t)p[off + 1] << 16) |
                     ((uint32_t)p[off + 2] << 8) | p[off + 3];
        off += 4; return v;
    }
    void skip(size_t k) { if (need(k)) off += k; }
};
} // namespace

bool IsJavaClassImage(const uint8_t* data, size_t n) {
    if (!data || n < 10) return false;
    if (data[0] != 0xCA || data[1] != 0xFE || data[2] != 0xBA || data[3] != 0xBE) return false;
    const uint16_t major = (uint16_t)((data[6] << 8) | data[7]);
    return major >= 45 && major <= 99;   // JDK 1.0 (45) .. far-future guard
}

// ---- constant pool -----------------------------------------------------------

static const size_t kMaxUtf8Stored = 4096;   // longer strings are truncated, not rejected

static bool parseCpEntries(Cur& c, uint16_t count, JvmClassFile& out) {
    out.cp.assign(count ? count : 1, JvmCpEntry{});   // 1-based; [0] stays tag 0
    for (uint16_t i = 1; i < count && !c.fail; ++i) {
        JvmCpEntry& e = out.cp[i];
        e.tag = c.u1();
        switch (e.tag) {
            case CP_Utf8: {
                const uint16_t len = c.u2();
                if (!c.need(len)) return false;
                e.utf8.assign((const char*)c.p + c.off, std::min<size_t>(len, kMaxUtf8Stored));
                c.off += len;
                break;
            }
            case CP_Integer: e.i32 = (int32_t)c.u4(); break;
            case CP_Float:   { uint32_t v = c.u4(); std::memcpy(&e.f32, &v, 4); break; }
            case CP_Long: {
                uint64_t hi = c.u4(), lo = c.u4();
                e.i64 = (int64_t)((hi << 32) | lo);
                ++i;                                   // Long/Double take two slots
                break;
            }
            case CP_Double: {
                uint64_t hi = c.u4(), lo = c.u4();
                uint64_t v = (hi << 32) | lo; std::memcpy(&e.f64, &v, 8);
                ++i;
                break;
            }
            case CP_Class: case CP_String: case CP_MethodType:
            case CP_Module: case CP_Package:
                e.a = c.u2(); break;
            case CP_Fieldref: case CP_Methodref: case CP_InterfaceMethodref:
            case CP_NameAndType: case CP_Dynamic: case CP_InvokeDynamic:
                e.a = c.u2(); e.b = c.u2(); break;
            case CP_MethodHandle:
                e.kind = c.u1(); e.a = c.u2(); break;
            default:
                return false;                          // unknown tag: can't know its width
        }
    }
    return !c.fail;
}

static bool parseConstantPool(Cur& c, JvmClassFile& out) {
    const uint16_t count = c.u2();
    if (c.fail) return false;
    return parseCpEntries(c, count, out);
}

bool ParseConstantPoolOnly(const uint8_t* data, size_t n, uint16_t count, JvmClassFile& out) {
    if (!data) return false;
    Cur c{data, n, 0, false};
    return parseCpEntries(c, count, out);
}

std::string JvmClassFile::utf8At(uint16_t idx) const {
    const JvmCpEntry* e = at(idx);
    return (e && e->tag == CP_Utf8) ? e->utf8 : std::string();
}

std::string JvmClassFile::classNameAt(uint16_t idx) const {
    const JvmCpEntry* e = at(idx);
    return (e && e->tag == CP_Class) ? utf8At(e->a) : std::string();
}

// Printable, escaped, capped copy of a string constant for inline comments.
static std::string escapeForComment(const std::string& s, size_t cap = 80) {
    std::string out; out.reserve(std::min(s.size(), cap) + 8);
    out.push_back('"');
    for (size_t i = 0; i < s.size(); ++i) {
        if (out.size() >= cap) { out += "\"..."; return out; }
        unsigned char ch = (unsigned char)s[i];
        switch (ch) {
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            default:
                if (ch >= 0x20 && ch < 0x7F) out.push_back((char)ch);
                else { char b[8]; std::snprintf(b, sizeof(b), "\\x%02X", ch); out += b; }
        }
    }
    out.push_back('"');
    return out;
}

std::string JvmClassFile::describeCp(uint16_t idx) const {
    const JvmCpEntry* e = at(idx);
    if (!e) return std::string();
    char buf[64];
    switch (e->tag) {
        case CP_Utf8:    return escapeForComment(e->utf8);
        case CP_Integer: std::snprintf(buf, sizeof(buf), "%d", e->i32); return buf;
        case CP_Float:   std::snprintf(buf, sizeof(buf), "%gf", (double)e->f32); return buf;
        case CP_Long:    std::snprintf(buf, sizeof(buf), "%lldL", (long long)e->i64); return buf;
        case CP_Double:  std::snprintf(buf, sizeof(buf), "%g", e->f64); return buf;
        case CP_Class:   return utf8At(e->a);
        case CP_String:  return escapeForComment(utf8At(e->a));
        case CP_NameAndType: {
            std::string n = utf8At(e->a), d = utf8At(e->b);
            return n.empty() ? n : n + ":" + d;
        }
        case CP_Fieldref: case CP_Methodref: case CP_InterfaceMethodref: {
            const std::string cls = classNameAt(e->a);
            std::string nt;
            if (const JvmCpEntry* p = at(e->b); p && p->tag == CP_NameAndType)
                nt = utf8At(p->a) + ":" + utf8At(p->b);
            if (cls.empty() && nt.empty()) return std::string();
            return cls.empty() ? nt : cls + "." + nt;
        }
        case CP_MethodType: return utf8At(e->a);
        case CP_Dynamic: case CP_InvokeDynamic: {
            if (const JvmCpEntry* p = at(e->b); p && p->tag == CP_NameAndType)
                return utf8At(p->a) + ":" + utf8At(p->b);
            return std::string();
        }
        case CP_Module: case CP_Package: return utf8At(e->a);
        default: return std::string();
    }
}

const JvmMethod* JvmClassFile::methodAtOffset(uint64_t off) const {
    // codeOffsets ascend in file order; binary-search the last start <= off.
    auto it = std::partition_point(methods.begin(), methods.end(),
        [off](const JvmMethod& m) { return (uint64_t)m.codeOffset <= off; });
    while (it != methods.begin()) {
        --it;
        if (!it->codeLength) continue;                  // abstract/native: no body
        if (off >= it->codeOffset && off < (uint64_t)it->codeOffset + it->codeLength)
            return &*it;
        break;                                          // starts ascend: earlier can't contain off
    }
    return nullptr;
}

uint16_t JvmClassFile::lineForBci(const JvmMethod& m, uint32_t bci) {
    uint16_t line = 0;
    for (const auto& [pc, ln] : m.lineNumbers) {        // sorted by pc
        if (pc > bci) break;
        line = ln;
    }
    return line;
}

// ---- fields / methods / attributes -------------------------------------------

// Parse one attribute_info header; returns the attribute name and positions the
// cursor at its payload. `len` is bounds-checked against the remaining buffer.
static bool attrHeader(Cur& c, const JvmClassFile& cf, std::string& name, uint32_t& len) {
    const uint16_t nameIdx = c.u2();
    len = c.u4();
    if (c.fail || !c.need(len)) return false;
    name = cf.utf8At(nameIdx);
    return true;
}

static bool parseCodeAttribute(Cur& c, const JvmClassFile& cf, uint32_t attrEnd, JvmMethod& m) {
    m.maxStack  = c.u2();
    m.maxLocals = c.u2();
    const uint32_t codeLen = c.u4();
    if (c.fail || !c.need(codeLen) || codeLen == 0) return false;
    m.codeOffset = (uint32_t)c.off;
    m.codeLength = codeLen;
    c.skip(codeLen);

    const uint16_t excCount = c.u2();
    for (uint16_t i = 0; i < excCount && !c.fail; ++i) {
        JvmExceptionHandler h;
        h.startPC = c.u2(); h.endPC = c.u2(); h.handlerPC = c.u2();
        h.catchTypeIndex = c.u2();
        m.handlers.push_back(h);
    }

    // Nested attributes: keep LineNumberTable, skip the rest.
    const uint16_t nAttr = c.u2();
    for (uint16_t i = 0; i < nAttr && !c.fail && c.off < attrEnd; ++i) {
        std::string an; uint32_t alen = 0;
        if (!attrHeader(c, cf, an, alen)) return false;
        const size_t payloadEnd = c.off + alen;
        if (an == "LineNumberTable") {
            const uint16_t cnt = c.u2();
            for (uint16_t k = 0; k < cnt && !c.fail; ++k) {
                uint16_t pc = c.u2(), ln = c.u2();
                m.lineNumbers.emplace_back(pc, ln);
            }
            std::sort(m.lineNumbers.begin(), m.lineNumbers.end());
        }
        c.off = payloadEnd;                             // resync regardless of parse depth
    }
    return !c.fail;
}

JvmClassFile ParseJavaClass(const uint8_t* data, size_t n) {
    JvmClassFile cf;
    auto bail = [&cf](const char* why) { cf.ok = false; cf.error = why; return cf; };
    if (!IsJavaClassImage(data, n)) return bail("not a Java class file");

    Cur c{data, n, 0, false};
    c.skip(4);                                          // magic
    cf.minorVersion = c.u2();
    cf.majorVersion = c.u2();

    if (!parseConstantPool(c, cf)) return bail("malformed constant pool");

    cf.accessFlags = c.u2();
    cf.thisClass   = cf.classNameAt(c.u2());
    cf.superClass  = cf.classNameAt(c.u2());

    const uint16_t nIfaces = c.u2();
    for (uint16_t i = 0; i < nIfaces && !c.fail; ++i)
        cf.interfaces.push_back(cf.classNameAt(c.u2()));

    // fields
    const uint16_t nFields = c.u2();
    for (uint16_t i = 0; i < nFields && !c.fail; ++i) {
        JvmField f;
        f.accessFlags = c.u2();
        f.name        = cf.utf8At(c.u2());
        f.descriptor  = cf.utf8At(c.u2());
        const uint16_t nAttr = c.u2();
        for (uint16_t k = 0; k < nAttr && !c.fail; ++k) {
            std::string an; uint32_t alen = 0;
            if (!attrHeader(c, cf, an, alen)) return bail("malformed field attribute");
            c.skip(alen);
        }
        cf.fields.push_back(std::move(f));
    }
    if (c.fail) return bail("malformed fields");

    // methods
    const uint16_t nMethods = c.u2();
    for (uint16_t i = 0; i < nMethods && !c.fail; ++i) {
        JvmMethod m;
        m.accessFlags = c.u2();
        m.name        = cf.utf8At(c.u2());
        m.descriptor  = cf.utf8At(c.u2());
        const uint16_t nAttr = c.u2();
        for (uint16_t k = 0; k < nAttr && !c.fail; ++k) {
            std::string an; uint32_t alen = 0;
            if (!attrHeader(c, cf, an, alen)) return bail("malformed method attribute");
            const size_t payloadEnd = c.off + alen;
            if (an == "Code") {
                if (!parseCodeAttribute(c, cf, (uint32_t)payloadEnd, m))
                    return bail("malformed Code attribute");
            }
            c.off = payloadEnd;
        }
        cf.methods.push_back(std::move(m));
    }
    if (c.fail) return bail("malformed methods");

    // class attributes: keep SourceFile, skip the rest
    const uint16_t nAttr = c.u2();
    for (uint16_t k = 0; k < nAttr && !c.fail; ++k) {
        std::string an; uint32_t alen = 0;
        if (!attrHeader(c, cf, an, alen)) break;        // trailing junk: keep what we have
        const size_t payloadEnd = c.off + alen;
        if (an == "SourceFile") cf.sourceFile = cf.utf8At(c.u2());
        c.off = payloadEnd;
    }

    cf.ok = true;
    return cf;
}

// ---- descriptor pretty-printing ----------------------------------------------

std::string JvmShortClassName(const std::string& internalName) {
    const size_t s = internalName.find_last_of('/');
    return s == std::string::npos ? internalName : internalName.substr(s + 1);
}

// Consume one field type at desc[i], appending its pretty form. Returns the
// index past the type (or std::string::npos on malformed input).
static size_t prettyType(const std::string& d, size_t i, std::string& out) {
    int dims = 0;
    while (i < d.size() && d[i] == '[') { ++dims; ++i; }
    if (i >= d.size()) return std::string::npos;
    switch (d[i]) {
        case 'B': out += "byte";    ++i; break;
        case 'C': out += "char";    ++i; break;
        case 'D': out += "double";  ++i; break;
        case 'F': out += "float";   ++i; break;
        case 'I': out += "int";     ++i; break;
        case 'J': out += "long";    ++i; break;
        case 'S': out += "short";   ++i; break;
        case 'Z': out += "boolean"; ++i; break;
        case 'V': out += "void";    ++i; break;
        case 'L': {
            const size_t semi = d.find(';', i);
            if (semi == std::string::npos) return std::string::npos;
            out += JvmShortClassName(d.substr(i + 1, semi - i - 1));
            i = semi + 1;
            break;
        }
        default: return std::string::npos;
    }
    for (int k = 0; k < dims; ++k) out += "[]";
    return i;
}

std::string JvmPrettyMethod(const std::string& name, const std::string& descriptor) {
    if (descriptor.size() < 3 || descriptor[0] != '(')
        return name + descriptor;                       // not a method descriptor: raw
    std::string params;
    size_t i = 1;
    while (i < descriptor.size() && descriptor[i] != ')') {
        if (!params.empty()) params += ", ";
        i = prettyType(descriptor, i, params);
        if (i == std::string::npos) return name + descriptor;
    }
    if (i >= descriptor.size()) return name + descriptor;
    std::string ret;
    if (prettyType(descriptor, i + 1, ret) == std::string::npos) ret = "?";
    return ret + " " + name + "(" + params + ")";
}

} // namespace ds
