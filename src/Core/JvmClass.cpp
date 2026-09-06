#include "JvmClass.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>

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

// CONSTANT_Utf8 uses modified UTF-8: U+0000 is C0 80 and supplementary
// characters are encoded as two three-byte UTF-16 surrogate units.  The model
// always stores valid UTF-8.  Invalid bytes and lone UTF-16 surrogates become
// U+FFFD, while JvmUtf8Status preserves exactly why the decoded text is lossy.
// The cap affects storage only; the entire input is still validated.
static void appendUtf8(uint32_t cp, std::string& out, bool& storing,
                       JvmUtf8Status& status) {
    if (!storing) return;
    char bytes[4];
    size_t count = 0;
    if (cp <= 0x7F) {
        bytes[count++] = (char)cp;
    } else if (cp <= 0x7FF) {
        bytes[count++] = (char)(0xC0 | (cp >> 6));
        bytes[count++] = (char)(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
        bytes[count++] = (char)(0xE0 | (cp >> 12));
        bytes[count++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        bytes[count++] = (char)(0x80 | (cp & 0x3F));
    } else {
        bytes[count++] = (char)(0xF0 | (cp >> 18));
        bytes[count++] = (char)(0x80 | ((cp >> 12) & 0x3F));
        bytes[count++] = (char)(0x80 | ((cp >> 6) & 0x3F));
        bytes[count++] = (char)(0x80 | (cp & 0x3F));
    }
    if (out.size() > kMaxUtf8Stored - count) {
        status |= JvmUtf8Status::OutputTruncated;
        storing = false;
        return;
    }
    out.append(bytes, count);
}

static JvmUtf8Status decodeModifiedUtf8(const uint8_t* p, size_t n,
                                        std::string& out) {
    out.clear();
    out.reserve(std::min(n, kMaxUtf8Stored));
    bool storing = true;
    JvmUtf8Status status = JvmUtf8Status::Valid;
    auto replacement = [&]() { appendUtf8(0xFFFD, out, storing, status); };
    for (size_t i = 0; i < n;) {
        uint32_t cp = 0;
        const uint8_t first = p[i];
        if (first > 0 && first < 0x80) {
            cp = first;
            ++i;
            appendUtf8(cp, out, storing, status);
            continue;
        }

        if ((first & 0xE0) == 0xC0) {
            if (n - i < 2) {
                status |= JvmUtf8Status::TruncatedEncoding;
                replacement();
                break;
            }
            if ((p[i + 1] & 0xC0) != 0x80) {
                status |= JvmUtf8Status::InvalidEncoding;
                replacement();
                ++i; // preserve the following byte for independent recovery
                continue;
            }
            cp = ((uint32_t)(first & 0x1F) << 6) | (p[i + 1] & 0x3F);
            // C0 80 is the one permitted overlong form (modified UTF-8 NUL).
            if ((first == 0xC0 && p[i + 1] != 0x80) || first == 0xC1 ||
                (cp != 0 && cp < 0x80)) {
                status |= JvmUtf8Status::InvalidEncoding;
                replacement();
                i += 2;
                continue;
            }
            i += 2;
            appendUtf8(cp, out, storing, status);
            continue;
        }

        if ((first & 0xF0) == 0xE0) {
            if (n - i < 3) {
                status |= JvmUtf8Status::TruncatedEncoding;
                replacement();
                break;
            }
            if ((p[i + 1] & 0xC0) != 0x80 || (p[i + 2] & 0xC0) != 0x80) {
                status |= JvmUtf8Status::InvalidEncoding;
                replacement();
                ++i;
                continue;
            }
            cp = ((uint32_t)(first & 0x0F) << 12) |
                 ((uint32_t)(p[i + 1] & 0x3F) << 6) | (p[i + 2] & 0x3F);
            if (cp < 0x800) {
                status |= JvmUtf8Status::InvalidEncoding; // overlong form
                replacement();
                i += 3;
                continue;
            }
            i += 3;

            if (cp >= 0xD800 && cp <= 0xDBFF) {
                // Normalize a complete surrogate pair. A lone Java UTF-16
                // surrogate has no valid UTF-8 scalar representation.
                if (n - i >= 3 && (p[i] & 0xF0) == 0xE0 &&
                    (p[i + 1] & 0xC0) == 0x80 && (p[i + 2] & 0xC0) == 0x80) {
                    const uint32_t low = ((uint32_t)(p[i] & 0x0F) << 12) |
                                         ((uint32_t)(p[i + 1] & 0x3F) << 6) |
                                         (p[i + 2] & 0x3F);
                    if (low >= 0xDC00 && low <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                        i += 3;
                    }
                }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    status |= JvmUtf8Status::UnpairedSurrogate;
                    replacement();
                    continue;
                }
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                status |= JvmUtf8Status::UnpairedSurrogate;
                replacement();
                continue;
            }
            appendUtf8(cp, out, storing, status);
            continue;
        }

        // Includes raw NUL, continuation bytes, and standard UTF-8's four-byte
        // form, none of which is legal in CONSTANT_Utf8. Consume a complete
        // four-byte UTF-8 sequence as one invalid unit to avoid four U+FFFDs.
        status |= JvmUtf8Status::InvalidEncoding;
        replacement();
        if (first >= 0xF0 && first <= 0xF4 && n - i >= 4 &&
            (p[i + 1] & 0xC0) == 0x80 && (p[i + 2] & 0xC0) == 0x80 &&
            (p[i + 3] & 0xC0) == 0x80)
            i += 4;
        else
            ++i;
    }
    return status;
}

static bool parseCpEntries(Cur& c, uint16_t count, JvmClassFile& out) {
    if (count == 0) return false;
    out.cp.assign(count, JvmCpEntry{});               // 1-based; [0] stays tag 0
    for (size_t i = 1; i < count && !c.fail; ++i) {
        JvmCpEntry& e = out.cp[i];
        e.tag = c.u1();
        switch (e.tag) {
            case CP_Utf8: {
                const uint16_t len = c.u2();
                if (!c.need(len)) return false;
                e.utf8Status = decodeModifiedUtf8(c.p + c.off, len, e.utf8);
                c.off += len;
                break;
            }
            case CP_Integer: e.i32 = (int32_t)c.u4(); break;
            case CP_Float:   { uint32_t v = c.u4(); std::memcpy(&e.f32, &v, 4); break; }
            case CP_Long: {
                if (i + 1 >= count) return false;        // required unusable pad slot
                uint64_t hi = c.u4(), lo = c.u4();
                e.i64 = (int64_t)((hi << 32) | lo);
                ++i;                                   // Long/Double take two slots
                break;
            }
            case CP_Double: {
                if (i + 1 >= count) return false;        // required unusable pad slot
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

JvmUtf8Status JvmClassFile::utf8StatusAt(uint16_t idx) const {
    const JvmCpEntry* e = at(idx);
    return (e && e->tag == CP_Utf8) ? e->utf8Status : JvmUtf8Status::Valid;
}

bool JvmClassFile::hasUtf8Issues() const {
    return std::any_of(cp.begin(), cp.end(), [](const JvmCpEntry& entry) {
        return entry.tag == CP_Utf8 && entry.utf8Status != JvmUtf8Status::Valid;
    });
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
    // Code-bearing methods ascend in file order, but abstract/native methods
    // retain codeOffset == 0 wherever they were declared. Those zero sentinels
    // make the full vector unsuitable for partition_point/lower_bound.
    const JvmMethod* candidate = nullptr;
    for (const JvmMethod& method : methods) {
        if (!method.codeLength) continue;
        if ((uint64_t)method.codeOffset > off) break;
        candidate = &method;
    }
    if (candidate && off - candidate->codeOffset < candidate->codeLength)
        return candidate;
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
    const JvmCpEntry* nameEntry = cf.at(nameIdx);
    if (!nameEntry || nameEntry->tag != CP_Utf8) return false;
    name = nameEntry->utf8;
    return true;
}

static bool parseCodeAttribute(Cur& c, const JvmClassFile& cf, size_t attrEnd, JvmMethod& m) {
    if (attrEnd < c.off || attrEnd > c.n) return false;
    Cur body{c.p, attrEnd, c.off, false};                // hard parent-attribute boundary

    m.maxStack  = body.u2();
    m.maxLocals = body.u2();
    const uint32_t codeLen = body.u4();
    if (body.fail || codeLen == 0 || codeLen >= 65536 || !body.need(codeLen) ||
        body.off > std::numeric_limits<uint32_t>::max())
        return false;
    m.codeOffset = (uint32_t)body.off;
    m.codeLength = codeLen;
    body.skip(codeLen);

    const uint16_t excCount = body.u2();
    if (body.fail || !body.need((size_t)excCount * 8)) return false;
    m.handlers.reserve(excCount);
    for (uint16_t i = 0; i < excCount; ++i) {
        JvmExceptionHandler h;
        h.startPC = body.u2(); h.endPC = body.u2(); h.handlerPC = body.u2();
        h.catchTypeIndex = body.u2();
        if (h.startPC >= h.endPC || h.endPC > codeLen || h.handlerPC >= codeLen)
            return false;
        if (h.catchTypeIndex != 0) {
            const JvmCpEntry* catchType = cf.at(h.catchTypeIndex);
            if (!catchType || catchType->tag != CP_Class) return false;
        }
        m.handlers.push_back(h);
    }

    // Nested attributes: keep LineNumberTable, skip the rest.
    const uint16_t nAttr = body.u2();
    if (body.fail) return false;
    static constexpr size_t kMaxLineNumbers = 65536;
    for (uint16_t i = 0; i < nAttr; ++i) {
        std::string an; uint32_t alen = 0;
        if (!attrHeader(body, cf, an, alen)) return false;
        const size_t payloadEnd = body.off + alen;
        if (an == "LineNumberTable") {
            Cur lines{body.p, payloadEnd, body.off, false};
            const uint16_t cnt = lines.u2();
            if (lines.fail || !lines.need((size_t)cnt * 4) ||
                m.lineNumbers.size() > kMaxLineNumbers - cnt)
                return false;
            for (uint16_t k = 0; k < cnt; ++k) {
                uint16_t pc = lines.u2(), ln = lines.u2();
                if (pc >= codeLen) return false;
                m.lineNumbers.emplace_back(pc, ln);
            }
            if (lines.fail || lines.off != payloadEnd) return false;
        }
        body.off = payloadEnd;
    }
    if (body.fail || body.off != attrEnd) return false; // no spill or unclaimed tail bytes
    std::sort(m.lineNumbers.begin(), m.lineNumbers.end());
    c.off = attrEnd;
    return true;
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
        bool sawCode = false;
        for (uint16_t k = 0; k < nAttr && !c.fail; ++k) {
            std::string an; uint32_t alen = 0;
            if (!attrHeader(c, cf, an, alen)) return bail("malformed method attribute");
            const size_t payloadEnd = c.off + alen;
            if (an == "Code") {
                if (sawCode || !parseCodeAttribute(c, cf, payloadEnd, m))
                    return bail("malformed Code attribute");
                sawCode = true;
            }
            c.off = payloadEnd;
        }
        cf.methods.push_back(std::move(m));
    }
    if (c.fail) return bail("malformed methods");

    // Class attributes: keep SourceFile, skip the rest. Unlike the former
    // best-effort tail, every declared attribute must be wholly present: the
    // class-file grammar ends here, so truncation or trailing bytes are errors.
    const uint16_t nAttr = c.u2();
    if (c.fail) return bail("malformed class attributes");
    bool sawSourceFile = false;
    for (uint16_t k = 0; k < nAttr && !c.fail; ++k) {
        std::string an; uint32_t alen = 0;
        if (!attrHeader(c, cf, an, alen)) return bail("malformed class attribute");
        const size_t payloadEnd = c.off + alen;
        if (an == "SourceFile") {
            if (sawSourceFile || alen != 2) return bail("malformed SourceFile attribute");
            const uint16_t sourceIndex = c.u2();
            const JvmCpEntry* source = cf.at(sourceIndex);
            if (c.fail || !source || source->tag != CP_Utf8)
                return bail("malformed SourceFile attribute");
            cf.sourceFile = source->utf8;
            sawSourceFile = true;
        }
        c.off = payloadEnd;
    }
    if (c.fail) return bail("malformed class attributes");
    if (c.off != n) return bail("trailing bytes after class file");

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
