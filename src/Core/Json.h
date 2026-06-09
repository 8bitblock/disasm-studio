#pragma once
//
// Json.h
// A tiny, dependency-free JSON value + parser + serializer. Just enough to back
// the project-sidecar persistence (objects, arrays, strings, numbers, bools,
// null). Numbers are stored as double; 64-bit addresses are persisted as hex
// strings by the Project layer to avoid float precision loss.
//
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ds::json {

enum class Type { Null, Bool, Num, Str, Arr, Obj };

struct Value {
    Type        type = Type::Null;
    bool        b    = false;
    double      num  = 0.0;
    std::string str;
    std::vector<Value>                        arr;
    std::vector<std::pair<std::string, Value>> obj;  // insertion-ordered

    Value() = default;

    static Value Null()              { return Value{}; }
    static Value Bool(bool v)        { Value x; x.type = Type::Bool; x.b = v; return x; }
    static Value Num(double v)       { Value x; x.type = Type::Num;  x.num = v; return x; }
    static Value Int(long long v)    { return Num((double)v); }
    static Value Str(std::string v)  { Value x; x.type = Type::Str;  x.str = std::move(v); return x; }
    static Value Arr()               { Value x; x.type = Type::Arr;  return x; }
    static Value Obj()               { Value x; x.type = Type::Obj;  return x; }

    bool isObj() const { return type == Type::Obj; }
    bool isArr() const { return type == Type::Arr; }
    bool isStr() const { return type == Type::Str; }
    bool isNum() const { return type == Type::Num; }

    // ---- object access ----
    void           set(const std::string& key, Value v);   // append or replace
    Value*         find(const std::string& key);
    const Value*   find(const std::string& key) const;
    void           push(Value v) { arr.push_back(std::move(v)); }  // array append

    // ---- typed scalar getters (with defaults) ----
    std::string asStr(const std::string& def = "") const { return type == Type::Str ? str : def; }
    double      asNum(double def = 0.0)             const { return type == Type::Num ? num : def; }
    long long   asInt(long long def = 0)            const { return type == Type::Num ? (long long)num : def; }
    bool        asBool(bool def = false)            const { return type == Type::Bool ? b : def; }

    // ---- object keyed getters ----
    std::string getStr(const std::string& key, const std::string& def = "") const;
    long long   getInt(const std::string& key, long long def = 0) const;
    bool        getBool(const std::string& key, bool def = false) const;
};

// Serialize. pretty=true indents with two spaces.
std::string Dump(const Value& v, bool pretty = true);

// Parse text into `out`. Returns false on syntax error (out left untouched).
bool Parse(const std::string& text, Value& out);

} // namespace ds::json
