#include "Json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <unordered_set>

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
    const JsonParseLimits& limits;
    size_t depth = 0;                       // current container nesting
    size_t nodes = 0;                       // scalar + container values
    size_t stringBytes = 0;                 // decoded keys and string values

    void skipWs() {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
    }

    bool parseValue(Value& out) {
        skipWs();
        if (p >= end) return false;
        if (nodes >= limits.maxNodes) return false;
        ++nodes;
        switch (*p) {
            case '{': {
                if (depth >= limits.maxDepth) return false;
                ++depth; bool ok = parseObject(out); --depth; return ok;
            }
            case '[': {
                if (depth >= limits.maxDepth) return false;
                ++depth; bool ok = parseArray(out); --depth; return ok;
            }
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
        auto take = [&]() {
            if (static_cast<size_t>(p - s) >= limits.maxNumberTokenBytes) return false;
            ++p;
            return true;
        };
        // RFC 8259 number grammar. In particular, leading '+', leading '.',
        // leading zeroes, a bare decimal point, and incomplete exponents are
        // malformed rather than values to be permissively repaired by strtod.
        if (p < end && *p == '-' && !take()) return false;
        if (p >= end) return false;
        if (*p == '0') {
            if (!take()) return false;
            if (p < end && *p >= '0' && *p <= '9') return false;
        } else if (*p >= '1' && *p <= '9') {
            do { if (!take()) return false; }
            while (p < end && *p >= '0' && *p <= '9');
        } else {
            return false;
        }
        if (p < end && *p == '.') {
            if (!take() || p >= end || *p < '0' || *p > '9') return false;
            do { if (!take()) return false; }
            while (p < end && *p >= '0' && *p <= '9');
        }
        if (p < end && (*p == 'e' || *p == 'E')) {
            if (!take()) return false;
            if (p < end && (*p == '+' || *p == '-'))
                if (!take()) return false;
            if (p >= end || *p < '0' || *p > '9') return false;
            do { if (!take()) return false; }
            while (p < end && *p >= '0' && *p <= '9');
        }
        std::string tok(s, p);
        char* e = nullptr;
        double d = std::strtod(tok.c_str(), &e);
        if (e != tok.c_str() + tok.size() || !std::isfinite(d)) return false;
        out = Value::Num(d);
        return true;
    }

    bool parseString(std::string& out) {
        if (p >= end || *p != '"') return false;
        ++p;
        const char* tokenStart = p;
        while (p < end) {
            if (static_cast<size_t>(p - tokenStart) >= limits.maxStringTokenBytes &&
                *p != '"')
                return false;
            char c = *p++;
            if (c == '"')
                return static_cast<size_t>((p - 1) - tokenStart) <= limits.maxStringTokenBytes &&
                       out.size() <= limits.maxStringTokenBytes;
            if (c == '\\') {
                if (p >= end) return false;
                char e = *p++;
                switch (e) {
                    case '"':  if (!appendByte(out, '"')) return false;  break;
                    case '\\': if (!appendByte(out, '\\')) return false; break;
                    case '/':  if (!appendByte(out, '/')) return false;  break;
                    case 'n':  if (!appendByte(out, '\n')) return false; break;
                    case 't':  if (!appendByte(out, '\t')) return false; break;
                    case 'r':  if (!appendByte(out, '\r')) return false; break;
                    case 'b':  if (!appendByte(out, '\b')) return false; break;
                    case 'f':  if (!appendByte(out, '\f')) return false; break;
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
                        if (!appendCodePoint(out, cp)) return false;
                        break;
                    }
                    default: return false;
                }
            } else {
                // RFC 8259 requires U+0000..U+001F to be escaped.
                if (static_cast<unsigned char>(c) < 0x20 || !appendByte(out, c)) return false;
            }
        }
        return false; // unterminated
    }

    bool appendByte(std::string& out, char value) {
        if (stringBytes >= limits.maxStringBytes || out.size() >= limits.maxStringTokenBytes)
            return false;
        out.push_back(value);
        ++stringBytes;
        return true;
    }

    bool appendCodePoint(std::string& out, unsigned cp) {
        char encoded[4]{};
        size_t count = 0;
        if (cp < 0x80) encoded[count++] = static_cast<char>(cp);
        else if (cp < 0x800) {
            encoded[count++] = static_cast<char>(0xC0 | (cp >> 6));
            encoded[count++] = static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            encoded[count++] = static_cast<char>(0xE0 | (cp >> 12));
            encoded[count++] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            encoded[count++] = static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            encoded[count++] = static_cast<char>(0xF0 | (cp >> 18));
            encoded[count++] = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            encoded[count++] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            encoded[count++] = static_cast<char>(0x80 | (cp & 0x3F));
        }
        if (count > limits.maxStringBytes || stringBytes > limits.maxStringBytes - count ||
            count > limits.maxStringTokenBytes || out.size() > limits.maxStringTokenBytes - count)
            return false;
        out.append(encoded, count);
        stringBytes += count;
        return true;
    }

    bool parseArray(Value& out) {
        ++p; // [
        out = Value::Arr();
        skipWs();
        if (p < end && *p == ']') { ++p; return true; }
        while (true) {
            if (out.arr.size() >= limits.maxContainerEntries) return false;
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
        // RFC 8259 permits parsers to choose how duplicate names are exposed,
        // but accepting them is unsafe for authoritative sidecars: a producer
        // and consumer can otherwise disagree about whether the first or last
        // value wins.  Check decoded names (so "a" and "\u0061" collide) at
        // every object depth.  The parser's per-container and cumulative
        // string budgets bound this auxiliary set, while hashing avoids the
        // quadratic scan that a hostile maximum-sized object would trigger.
        std::unordered_set<std::string> keys;
        skipWs();
        if (p < end && *p == '}') { ++p; return true; }
        while (true) {
            if (out.obj.size() >= limits.maxContainerEntries) return false;
            skipWs();
            std::string key;
            if (!parseString(key)) return false;
            if (!keys.emplace(key).second) return false;
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
    static const JsonParseLimits defaults{};
    return Parse(text, out, defaults);
}

bool Parse(const std::string& text, Value& out, const JsonParseLimits& limits) {
    if (!limits.maxDepth || !limits.maxNodes || !limits.maxStringBytes ||
        !limits.maxContainerEntries || !limits.maxStringTokenBytes ||
        !limits.maxNumberTokenBytes)
        return false;
    try {
        Parser ps{ text.c_str(), text.c_str() + text.size(), limits };
        Value v;
        if (!ps.parseValue(v)) return false;
        ps.skipWs();
        if (ps.p != ps.end) return false; // trailing garbage
        out = std::move(v);
        return true;
    } catch (const std::bad_alloc&) {
        return false;
    } catch (const std::length_error&) {
        return false;
    }
}

} // namespace ds::json
