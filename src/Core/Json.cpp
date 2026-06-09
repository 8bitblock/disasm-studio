#include "Json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace ds::json {

void Value::set(const std::string& key, Value v) {
    for (auto& kv : obj)
        if (kv.first == key) { kv.second = std::move(v); return; }
    type = Type::Obj;
    obj.emplace_back(key, std::move(v));
}

Value* Value::find(const std::string& key) {
    for (auto& kv : obj) if (kv.first == key) return &kv.second;
    return nullptr;
}
const Value* Value::find(const std::string& key) const {
    for (auto& kv : obj) if (kv.first == key) return &kv.second;
    return nullptr;
}

std::string Value::getStr(const std::string& key, const std::string& def) const {
    const Value* v = find(key); return v ? v->asStr(def) : def;
}
long long Value::getInt(const std::string& key, long long def) const {
    const Value* v = find(key); return v ? v->asInt(def) : def;
}
bool Value::getBool(const std::string& key, bool def) const {
    const Value* v = find(key); return v ? v->asBool(def) : def;
}

// ---------------------------------------------------------------- serialize --

static void escape(const std::string& s, std::string& out) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else          { out += (char)c; }
        }
    }
    out += '"';
}

static void numToStr(double n, std::string& out) {
    if (std::isnan(n) || std::isinf(n)) { out += '0'; return; }
    // Whole numbers (incl. addresses-as-numbers) print without a decimal point.
    if (n == std::floor(n) && std::fabs(n) < 9.0e15) {
        char b[32]; std::snprintf(b, sizeof(b), "%lld", (long long)n); out += b;
    } else {
        char b[40]; std::snprintf(b, sizeof(b), "%.17g", n); out += b;
    }
}

static void dump(const Value& v, bool pretty, int depth, std::string& out) {
    auto indent = [&](int d) { if (pretty) { out += '\n'; out.append((size_t)d * 2, ' '); } };
    switch (v.type) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += v.b ? "true" : "false"; break;
        case Type::Num:  numToStr(v.num, out); break;
        case Type::Str:  escape(v.str, out); break;
        case Type::Arr:
            if (v.arr.empty()) { out += "[]"; break; }
            out += '[';
            for (size_t i = 0; i < v.arr.size(); ++i) {
                if (i) out += ',';
                indent(depth + 1);
                dump(v.arr[i], pretty, depth + 1, out);
            }
            indent(depth); out += ']';
            break;
        case Type::Obj:
            if (v.obj.empty()) { out += "{}"; break; }
            out += '{';
            for (size_t i = 0; i < v.obj.size(); ++i) {
                if (i) out += ',';
                indent(depth + 1);
                escape(v.obj[i].first, out);
                out += pretty ? ": " : ":";
                dump(v.obj[i].second, pretty, depth + 1, out);
            }
            indent(depth); out += '}';
            break;
    }
}

std::string Dump(const Value& v, bool pretty) {
    std::string out;
    dump(v, pretty, 0, out);
    return out;
}

// -------------------------------------------------------------------- parse --

namespace {
struct Parser {
    const char* p;
    const char* end;
    int depth = 0;                          // current container nesting
    static constexpr int kMaxDepth = 200;   // reject pathologically deep input

    void skipWs() {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
    }

    bool parseValue(Value& out) {
        skipWs();
        if (p >= end) return false;
        if (depth >= kMaxDepth) return false;   // too deeply nested -> reject, don't overflow the stack
        switch (*p) {
            case '{': { ++depth; bool ok = parseObject(out); --depth; return ok; }
            case '[': { ++depth; bool ok = parseArray(out);  --depth; return ok; }
            case '"': { std::string s; if (!parseString(s)) return false; out = Value::Str(std::move(s)); return true; }
            case 't': return lit("true",  4) && (out = Value::Bool(true),  true);
            case 'f': return lit("false", 5) && (out = Value::Bool(false), true);
            case 'n': return lit("null",  4) && (out = Value::Null(),       true);
            default:  return parseNumber(out);
        }
    }

    bool lit(const char* s, int n) {
        if (end - p < n) return false;
        for (int i = 0; i < n; ++i) if (p[i] != s[i]) return false;
        p += n; return true;
    }

    bool parseNumber(Value& out) {
        const char* s = p;
        if (p < end && (*p == '-' || *p == '+')) ++p;
        bool any = false;
        while (p < end && ((*p >= '0' && *p <= '9') || *p == '.' || *p == 'e' || *p == 'E' || *p == '+' || *p == '-')) { ++p; any = true; }
        if (!any) return false;
        std::string tok(s, p);
        char* e = nullptr;
        double d = std::strtod(tok.c_str(), &e);
        if (e != tok.c_str() + tok.size()) return false;  // junk/malformed token ("1e", ".", "--5")
        out = Value::Num(d);
        return true;
    }

    bool parseString(std::string& out) {
        if (p >= end || *p != '"') return false;
        ++p;
        while (p < end) {
            char c = *p++;
            if (c == '"') return true;
            if (c == '\\') {
                if (p >= end) return false;
                char e = *p++;
                switch (e) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'n':  out += '\n'; break;
                    case 't':  out += '\t'; break;
                    case 'r':  out += '\r'; break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'u': {
                        if (end - p < 4) return false;
                        unsigned cp = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = *p++; cp <<= 4;
                            if      (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                            else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                            else return false;
                        }
                        // Combine UTF-16 surrogate pairs into a single code point.
                        if (cp >= 0xDC00 && cp <= 0xDFFF) return false;   // lone low surrogate
                        if (cp >= 0xD800 && cp <= 0xDBFF) {               // high surrogate: need a low one
                            if (end - p < 6 || p[0] != '\\' || p[1] != 'u') return false;
                            p += 2;
                            unsigned lo = 0;
                            for (int i = 0; i < 4; ++i) {
                                char h = *p++; lo <<= 4;
                                if      (h >= '0' && h <= '9') lo |= (unsigned)(h - '0');
                                else if (h >= 'a' && h <= 'f') lo |= (unsigned)(h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') lo |= (unsigned)(h - 'A' + 10);
                                else return false;
                            }
                            if (lo < 0xDC00 || lo > 0xDFFF) return false;
                            cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                        }
                        // Encode the code point as UTF-8.
                        if (cp < 0x80) out += (char)cp;
                        else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
                        else if (cp < 0x10000) { out += (char)(0xE0 | (cp >> 12)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
                        else { out += (char)(0xF0 | (cp >> 18)); out += (char)(0x80 | ((cp >> 12) & 0x3F)); out += (char)(0x80 | ((cp >> 6) & 0x3F)); out += (char)(0x80 | (cp & 0x3F)); }
                        break;
                    }
                    default: return false;
                }
            } else {
                out += c;
            }
        }
        return false; // unterminated
    }

    bool parseArray(Value& out) {
        ++p; // [
        out = Value::Arr();
        skipWs();
        if (p < end && *p == ']') { ++p; return true; }
        while (true) {
            Value v;
            if (!parseValue(v)) return false;
            out.arr.push_back(std::move(v));
            skipWs();
            if (p >= end) return false;
            if (*p == ',') { ++p; continue; }
            if (*p == ']') { ++p; return true; }
            return false;
        }
    }

    bool parseObject(Value& out) {
        ++p; // {
        out = Value::Obj();
        skipWs();
        if (p < end && *p == '}') { ++p; return true; }
        while (true) {
            skipWs();
            std::string key;
            if (!parseString(key)) return false;
            skipWs();
            if (p >= end || *p != ':') return false;
            ++p;
            Value v;
            if (!parseValue(v)) return false;
            out.obj.emplace_back(std::move(key), std::move(v));
            skipWs();
            if (p >= end) return false;
            if (*p == ',') { ++p; continue; }
            if (*p == '}') { ++p; return true; }
            return false;
        }
    }
};
} // namespace

bool Parse(const std::string& text, Value& out) {
    Parser ps{ text.c_str(), text.c_str() + text.size() };
    Value v;
    if (!ps.parseValue(v)) return false;
    ps.skipWs();
    if (ps.p != ps.end) return false; // trailing garbage
    out = std::move(v);
    return true;
}

} // namespace ds::json
