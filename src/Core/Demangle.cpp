#include "Demangle.h"
#include "DbgHelpLock.h"

#include <windows.h>
#include <dbghelp.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "dbghelp.lib")

namespace ds {
namespace {

constexpr size_t kMaxInput       = 4096;
constexpr size_t kMaxOutput      = 16384;
constexpr size_t kMaxDepth       = 64;
constexpr size_t kMaxComponents  = 1024;
constexpr size_t kMaxCache       = 32768;

static bool allDigits(std::string_view s) {
    if (s.empty()) return false;
    for (unsigned char c : s) if (!std::isdigit(c)) return false;
    return true;
}

static std::string join(const std::vector<std::string>& values, std::string_view sep) {
    std::string out;
    for (const std::string& value : values) {
        if (!out.empty()) out.append(sep);
        if (out.size() + value.size() > kMaxOutput) return {};
        out += value;
    }
    return out;
}

static std::string unqualifiedBase(std::string value) {
    const size_t scope = value.rfind("::");
    if (scope != std::string::npos) value.erase(0, scope + 2);
    const size_t templ = value.find('<');
    if (templ != std::string::npos) value.erase(templ);
    return value.empty() ? std::string("<anonymous>") : value;
}

class ItaniumParser {
public:
    explicit ItaniumParser(std::string_view input) : s_(input) {}

    DemangleResult run() {
        DemangleResult r;
        r.scheme = DemangleScheme::Itanium;
        if (s_.size() < 3 || !s_.starts_with("_Z")) { r.text.assign(s_); return r; }
        pos_ = 2;
        std::string value;
        if (!parseEncoding(value, 0) || value.empty() || value.size() > kMaxOutput) {
            r.text.assign(s_);
            r.label = r.text;
            r.scheme = DemangleScheme::None;
            return r;
        }
        // GCC/Clang clone/version suffixes are outside the ABI encoding. Preserve
        // them because they distinguish real addresses, but keep the readable core.
        if (pos_ < s_.size()) {
            const std::string_view suffix = s_.substr(pos_);
            if (suffix[0] != '.' && suffix[0] != '@') {
                r.text.assign(s_);
                r.label = r.text;
                r.scheme = DemangleScheme::None;
                return r;
            }
            if (value.size() + suffix.size() + 1 > kMaxOutput) {
                r.text.assign(s_);
                r.scheme = DemangleScheme::None;
                return r;
            }
            value.push_back(' ');
            value.append(suffix);
            if (!topLabel_.empty()) {
                topLabel_.push_back(' ');
                topLabel_.append(suffix);
            }
        }
        r.complete = pos_ == s_.size() || s_[pos_] == '.' || s_[pos_] == '@';
        r.text = std::move(value);
        r.label = topLabel_.empty() ? r.text : topLabel_;
        return r;
    }

private:
    struct NameResult {
        std::string text;
        std::string qualifiers;
        bool finalTemplate = false;
        bool ctorOrDtor = false;
    };

    struct DepthGuard {
        ItaniumParser& p;
        bool ok = false;
        explicit DepthGuard(ItaniumParser& parser) : p(parser) {
            if (p.depth_ < kMaxDepth) { ++p.depth_; ok = true; }
        }
        ~DepthGuard() { if (ok) --p.depth_; }
    };

    bool atEnd() const { return pos_ >= s_.size(); }
    char peek(size_t n = 0) const { return pos_ + n < s_.size() ? s_[pos_ + n] : '\0'; }
    bool take(char c) { if (peek() != c) return false; ++pos_; return true; }
    bool take(std::string_view v) {
        if (s_.substr(pos_, v.size()) != v) return false;
        pos_ += v.size();
        return true;
    }

    bool parseEncoding(std::string& out, char terminator) {
        DepthGuard guard(*this); if (!guard.ok) return false;
        if (parseSpecial(out, terminator)) return true;

        NameResult name;
        if (!parseName(name)) return false;
        if (depth_ == 1 && topLabel_.empty()) topLabel_ = name.text;
        if (terminator && peek() == terminator) { out = std::move(name.text); return true; }
        if (!terminator && atEnd()) { out = std::move(name.text); return true; }

        std::vector<std::string> types;
        while (!atEnd() && (!terminator || peek() != terminator) && peek() != '.' && peek() != '@') {
            std::string type;
            if (!parseType(type) || type.empty()) return false;
            types.push_back(std::move(type));
            if (types.size() > kMaxComponents) return false;
        }
        if (types.size() == 1 && types[0] == "void") types.clear();

        std::string returnType;
        // The ABI encodes a return type for function-template names (but not
        // constructors/destructors/conversions). Class-template components do
        // not trigger this; parseName tracks only the final component.
        if (name.finalTemplate && !name.ctorOrDtor && !types.empty()) {
            returnType = std::move(types.front());
            types.erase(types.begin());
        }
        if (types.size() == 1 && types[0] == "void") types.clear();
        const std::string args = join(types, ", ");
        if (!types.empty() && args.empty()) return false;
        out = name.text + "(" + args + ")";
        out += name.qualifiers;
        if (!returnType.empty()) out = returnType + " " + out;
        return out.size() <= kMaxOutput;
    }

    bool parseSpecial(std::string& out, char terminator) {
        const size_t save = pos_;
        struct Prefix { const char* code; const char* text; bool type; };
        static constexpr Prefix prefixes[] = {
            {"TV", "vtable for ", true}, {"TT", "VTT for ", true},
            {"TI", "typeinfo for ", true}, {"TS", "typeinfo name for ", true},
            {"GV", "guard variable for ", false}, {"TH", "thread-local initialization for ", false},
            {"TW", "thread-local wrapper for ", false},
        };
        for (const Prefix& p : prefixes) {
            if (!take(p.code)) continue;
            std::string target;
            if (p.type) {
                if (!parseType(target)) { pos_ = save; return false; }
            } else {
                NameResult name;
                if (!parseName(name)) { pos_ = save; return false; }
                target = std::move(name.text);
            }
            out = std::string(p.text) + target;
            return true;
        }

        const char* thunk = nullptr;
        if (take("Th")) thunk = "non-virtual thunk to ";
        else if (take("Tv")) thunk = "virtual thunk to ";
        else if (take("Tc")) thunk = "covariant return thunk to ";
        if (thunk) {
            // One offset for Th/Tv, two for Tc. Their values are useful to ABI
            // machinery but noisy in an analyst-facing label, so validate/skip.
            const int count = save + 2 <= s_.size() && s_.substr(save, 2) == "Tc" ? 2 : 1;
            for (int i = 0; i < count; ++i) if (!skipCallOffset()) { pos_ = save; return false; }
            std::string target;
            if (!parseEncoding(target, terminator)) { pos_ = save; return false; }
            out = std::string(thunk) + target;
            return true;
        }
        if (take("GTt") || take("GTn")) {
            const bool non = s_.substr(save, 3) == "GTn";
            std::string target;
            if (!parseEncoding(target, terminator)) { pos_ = save; return false; }
            out = std::string(non ? "non-transaction clone for " : "transaction clone for ") + target;
            return true;
        }
        pos_ = save;
        return false;
    }

    bool skipNumber(bool allowNegative = true) {
        if (allowNegative && peek() == 'n') ++pos_;
        const size_t begin = pos_;
        while (std::isdigit((unsigned char)peek())) ++pos_;
        return pos_ != begin;
    }

    bool skipCallOffset() {
        if (take('h')) return skipNumber() && take('_');
        if (take('v')) return skipNumber() && take('_') && skipNumber() && take('_');
        return false;
    }

    bool parseName(NameResult& out) {
        DepthGuard guard(*this); if (!guard.ok) return false;
        if (take('N')) return parseNestedName(out);
        if (take('Z')) return parseLocalName(out);

        std::vector<std::string> pieces;
        bool finalTemplate = false, ctorDtor = false;
        if (take("St")) pieces.push_back("std");

        std::string component;
        if (!parseNameComponent(component, pieces.empty() ? std::string() : pieces.back(),
                                finalTemplate, ctorDtor))
            return false;
        pieces.push_back(std::move(component));
        out.text = join(pieces, "::");
        out.finalTemplate = finalTemplate;
        out.ctorOrDtor = ctorDtor;
        if (out.text.empty()) return false;
        remember(out.text);
        return true;
    }

    bool parseNestedName(NameResult& out) {
        // CV/ref qualifiers apply to the member function, not the path spelling.
        std::vector<std::string> suffixQualifiers;
        while (peek() == 'K' || peek() == 'V' || peek() == 'r' || peek() == 'R' || peek() == 'O') {
            const char q = s_[pos_++];
            if (q == 'K') suffixQualifiers.push_back("const");
            else if (q == 'V') suffixQualifiers.push_back("volatile");
            else if (q == 'r') suffixQualifiers.push_back("restrict");
            else if (q == 'R') suffixQualifiers.push_back("&");
            else suffixQualifiers.push_back("&&");
        }

        std::vector<std::string> pieces;
        bool lastTemplate = false, lastCtorDtor = false;
        while (!atEnd() && peek() != 'E') {
            if (pieces.size() >= kMaxComponents) return false;
            if (take("St")) {
                pieces.push_back("std");
                continue;
            }
            std::string component;
            bool templ = false, ctorDtor = false;
            const std::string scope = pieces.empty() ? std::string() : pieces.back();
            if (!parseNameComponent(component, scope, templ, ctorDtor)) return false;
            pieces.push_back(std::move(component));
            lastTemplate = templ;
            lastCtorDtor = ctorDtor;
            remember(join(pieces, "::"));
        }
        if (!take('E') || pieces.empty()) return false;
        out.text = join(pieces, "::");
        for (const std::string& q : suffixQualifiers) out.qualifiers += " " + q;
        out.finalTemplate = lastTemplate;
        out.ctorOrDtor = lastCtorDtor;
        return !out.text.empty() && out.text.size() <= kMaxOutput;
    }

    bool parseLocalName(NameResult& out) {
        std::string enclosing;
        if (!parseEncoding(enclosing, 'E') || !take('E')) return false;
        std::string entity;
        bool templ = false, ctorDtor = false;
        if (take('s')) entity = "string literal";
        else if (!parseNameComponent(entity, {}, templ, ctorDtor)) return false;
        // Optional discriminator: _<number> or __<number>_.
        if (take('_')) {
            take('_');
            while (std::isdigit((unsigned char)peek())) ++pos_;
            take('_');
        }
        out.text = enclosing + "::" + entity;
        out.finalTemplate = templ;
        out.ctorOrDtor = ctorDtor;
        remember(out.text);
        return out.text.size() <= kMaxOutput;
    }

    bool parseNameComponent(std::string& out, const std::string& scope,
                            bool& wasTemplate, bool& ctorDtor) {
        wasTemplate = false;
        ctorDtor = false;
        if (std::isdigit((unsigned char)peek())) {
            if (!parseSourceName(out)) return false;
        } else if (peek() == 'S') {
            if (!parseSubstitution(out)) return false;
        } else {
            std::string op;
            if (parseCtorDtor(op, scope)) { out = std::move(op); ctorDtor = true; }
            else if (parseOperator(op)) out = std::move(op);
            else return false;
        }

        if (peek() == 'I') {
            std::vector<std::string> args;
            if (!parseTemplateArgs(args)) return false;
            const std::string joined = join(args, ", ");
            if (!args.empty() && joined.empty()) return false;
            out += "<" + joined + ">";
            wasTemplate = true;
        }
        while (take('B')) { // ABI tag
            std::string tag;
            if (!parseSourceName(tag)) return false;
            out += "[abi:" + tag + "]";
        }
        return out.size() <= kMaxOutput;
    }

    bool parseSourceName(std::string& out) {
        if (!std::isdigit((unsigned char)peek())) return false;
        size_t length = 0;
        const size_t digits = pos_;
        while (std::isdigit((unsigned char)peek())) {
            const unsigned d = (unsigned)(s_[pos_++] - '0');
            if (length > (kMaxInput - d) / 10) return false;
            length = length * 10 + d;
        }
        if (pos_ == digits || !length || length > kMaxInput || length > s_.size() - pos_) return false;
        out.assign(s_.substr(pos_, length));
        pos_ += length;
        return true;
    }

    bool parseCtorDtor(std::string& out, const std::string& scope) {
        if ((peek() != 'C' && peek() != 'D') || !std::isdigit((unsigned char)peek(1))) return false;
        const bool dtor = peek() == 'D';
        pos_ += 2;
        out = (dtor ? "~" : "") + unqualifiedBase(scope);
        return true;
    }

    bool parseOperator(std::string& out) {
        if (take("cv")) {
            std::string type;
            if (!parseType(type)) return false;
            out = "operator " + type;
            return true;
        }
        struct Op { const char code[3]; const char* text; };
        static constexpr Op ops[] = {
            {{'n','w','\0'}, "operator new"}, {{'n','a','\0'}, "operator new[]"},
            {{'d','l','\0'}, "operator delete"}, {{'d','a','\0'}, "operator delete[]"},
            {{'p','s','\0'}, "operator+"}, {{'n','g','\0'}, "operator-"},
            {{'a','d','\0'}, "operator&"}, {{'d','e','\0'}, "operator*"},
            {{'c','o','\0'}, "operator~"}, {{'p','l','\0'}, "operator+"},
            {{'m','i','\0'}, "operator-"}, {{'m','l','\0'}, "operator*"},
            {{'d','v','\0'}, "operator/"}, {{'r','m','\0'}, "operator%"},
            {{'a','n','\0'}, "operator&"}, {{'o','r','\0'}, "operator|"},
            {{'e','o','\0'}, "operator^"}, {{'a','S','\0'}, "operator="},
            {{'p','L','\0'}, "operator+="}, {{'m','I','\0'}, "operator-="},
            {{'m','L','\0'}, "operator*="}, {{'d','V','\0'}, "operator/="},
            {{'r','M','\0'}, "operator%="}, {{'a','N','\0'}, "operator&="},
            {{'o','R','\0'}, "operator|="}, {{'e','O','\0'}, "operator^="},
            {{'l','s','\0'}, "operator<<"}, {{'r','s','\0'}, "operator>>"},
            {{'l','S','\0'}, "operator<<="}, {{'r','S','\0'}, "operator>>="},
            {{'e','q','\0'}, "operator=="}, {{'n','e','\0'}, "operator!="},
            {{'l','t','\0'}, "operator<"}, {{'g','t','\0'}, "operator>"},
            {{'l','e','\0'}, "operator<="}, {{'g','e','\0'}, "operator>="},
            {{'s','s','\0'}, "operator<=>"}, {{'n','t','\0'}, "operator!"},
            {{'a','a','\0'}, "operator&&"}, {{'o','o','\0'}, "operator||"},
            {{'p','p','\0'}, "operator++"}, {{'m','m','\0'}, "operator--"},
            {{'c','m','\0'}, "operator,"}, {{'p','m','\0'}, "operator->*"},
            {{'p','t','\0'}, "operator->"}, {{'c','l','\0'}, "operator()"},
            {{'i','x','\0'}, "operator[]"}, {{'q','u','\0'}, "operator?"},
        };
        for (const Op& op : ops) if (take(std::string_view(op.code, 2))) { out = op.text; return true; }
        if (take("li")) {
            std::string suffix;
            if (!parseSourceName(suffix)) return false;
            out = "operator\"\" " + suffix;
            return true;
        }
        return false;
    }

    bool parseTemplateArgs(std::vector<std::string>& out) {
        if (!take('I')) return false;
        while (!atEnd() && peek() != 'E') {
            std::string arg;
            if (take('J')) {
                std::vector<std::string> pack;
                while (!atEnd() && peek() != 'E') {
                    std::string item;
                    if (!parseTemplateArg(item)) return false;
                    pack.push_back(std::move(item));
                }
                if (!take('E')) return false;
                arg = join(pack, ", ");
                if (pack.empty()) arg = "<empty pack>";
            } else if (!parseTemplateArg(arg)) return false;
            out.push_back(std::move(arg));
            if (out.size() > kMaxComponents) return false;
        }
        return take('E');
    }

    bool parseTemplateArg(std::string& out) {
        if (peek() == 'L') return parseLiteral(out);
        if (take('X')) {
            if (!parseExpression(out) || !take('E')) return false;
            return true;
        }
        return parseType(out);
    }

    bool parseLiteral(std::string& out) {
        if (!take('L')) return false;
        if (take("_Z")) {
            std::string encoding;
            if (!parseEncoding(encoding, 'E') || !take('E')) return false;
            out = "&" + encoding;
            return true;
        }
        std::string type;
        if (!parseType(type)) return false;
        const size_t begin = pos_;
        while (!atEnd() && peek() != 'E') ++pos_;
        if (!take('E')) return false;
        std::string value(s_.substr(begin, pos_ - begin - 1));
        if (!value.empty() && value[0] == 'n') value = "-" + value.substr(1);
        if (type == "bool") value = value == "0" ? "false" : "true";
        else if (type == "char" && value.size() <= 3 && allDigits(value)) {
            unsigned long v = 0; for (char c : value) v = v * 10 + (unsigned)(c - '0');
            if (v >= 0x20 && v < 0x7f) value = std::string("'") + (char)v + "'";
        }
        out = value.empty() ? ("(" + type + ")") : value;
        return true;
    }

    bool parseExpression(std::string& out) {
        // Common non-type template expressions. Unknown-but-balanced expression
        // forms degrade to an explicit marker instead of rejecting the symbol.
        if (take("ad")) { std::string v; if (!parseExpression(v)) return false; out = "&" + v; return true; }
        if (take("de")) { std::string v; if (!parseExpression(v)) return false; out = "*" + v; return true; }
        if (peek() == 'L') return parseLiteral(out);
        NameResult name;
        const size_t save = pos_;
        if (parseName(name)) { out = name.text; return true; }
        pos_ = save;
        std::string type;
        if (parseType(type)) { out = type; return true; }
        pos_ = save;
        return false;
    }

    bool parseType(std::string& out) {
        DepthGuard guard(*this); if (!guard.ok || atEnd()) return false;
        const char c = s_[pos_++];
        switch (c) {
            case 'v': out = "void"; return true; case 'w': out = "wchar_t"; return true;
            case 'b': out = "bool"; return true; case 'c': out = "char"; return true;
            case 'a': out = "signed char"; return true; case 'h': out = "unsigned char"; return true;
            case 's': out = "short"; return true; case 't': out = "unsigned short"; return true;
            case 'i': out = "int"; return true; case 'j': out = "unsigned int"; return true;
            case 'l': out = "long"; return true; case 'm': out = "unsigned long"; return true;
            case 'x': out = "long long"; return true; case 'y': out = "unsigned long long"; return true;
            case 'n': out = "__int128"; return true; case 'o': out = "unsigned __int128"; return true;
            case 'f': out = "float"; return true; case 'd': out = "double"; return true;
            case 'e': out = "long double"; return true; case 'g': out = "__float128"; return true;
            case 'z': out = "..."; return true;
            case 'P': { std::string t; if (!parseType(t)) return false; out = t + "*"; return true; }
            case 'R': { std::string t; if (!parseType(t)) return false; out = t + "&"; return true; }
            case 'O': { std::string t; if (!parseType(t)) return false; out = t + "&&"; return true; }
            case 'K': { std::string t; if (!parseType(t)) return false; out = "const " + t; return true; }
            case 'V': { std::string t; if (!parseType(t)) return false; out = "volatile " + t; return true; }
            case 'r': { std::string t; if (!parseType(t)) return false; out = "restrict " + t; return true; }
            case 'C': { std::string t; if (!parseType(t)) return false; out = "complex " + t; return true; }
            case 'G': { std::string t; if (!parseType(t)) return false; out = "imaginary " + t; return true; }
            case 'A': return parseArrayType(out);
            case 'F': return parseFunctionType(out);
            case 'M': {
                std::string cls, member;
                if (!parseType(cls) || !parseType(member)) return false;
                out = member + " " + cls + "::*"; return true;
            }
            case 'T': return parseTemplateParam(out);
            case 'S': --pos_; {
                NameResult n; if (!parseName(n)) return false;
                out = n.text; return true;
            }
            case 'N': case 'Z': --pos_; { NameResult n; if (!parseName(n)) return false; out = n.text; return true; }
            case 'U': {
                std::string qualifier, t;
                if (!parseSourceName(qualifier) || !parseType(t)) return false;
                out = qualifier + " " + t; return true;
            }
            case 'u': return parseSourceName(out);
            case 'D': return parseDType(out);
            default:
                if (std::isdigit((unsigned char)c)) { --pos_; NameResult n; if (!parseName(n)) return false; out = n.text; return true; }
                --pos_; return false;
        }
    }

    bool parseArrayType(std::string& out) {
        std::string dimension;
        if (peek() == '_') ++pos_;
        else {
            const size_t begin = pos_;
            while (std::isdigit((unsigned char)peek())) ++pos_;
            if (pos_ == begin || !take('_')) return false;
            dimension.assign(s_.substr(begin, pos_ - begin - 1));
        }
        std::string element;
        if (!parseType(element)) return false;
        out = element + "[" + dimension + "]";
        return true;
    }

    bool parseFunctionType(std::string& out) {
        take('Y'); // extern "C"
        std::vector<std::string> types;
        while (!atEnd() && peek() != 'E') {
            std::string t; if (!parseType(t)) return false;
            types.push_back(std::move(t));
            if (types.size() > kMaxComponents) return false;
        }
        if (!take('E') || types.empty()) return false;
        std::string ret = types.front(); types.erase(types.begin());
        if (types.size() == 1 && types[0] == "void") types.clear();
        const std::string args = join(types, ", ");
        if (!types.empty() && args.empty()) return false;
        out = ret + " (" + args + ")";
        return true;
    }

    bool parseTemplateParam(std::string& out) {
        uint64_t index = 0;
        if (take('_')) { out = "T0"; return true; }
        const size_t begin = pos_;
        while (std::isalnum((unsigned char)peek())) {
            const char c = s_[pos_++];
            const unsigned digit = std::isdigit((unsigned char)c) ? c - '0'
                                 : std::isupper((unsigned char)c) ? c - 'A' + 10 : c - 'a' + 10;
            if (digit >= 36 || index > (UINT64_MAX - digit) / 36) return false;
            index = index * 36 + digit;
        }
        if (pos_ == begin || !take('_')) return false;
        out = "T" + std::to_string(index + 1);
        return true;
    }

    bool parseDType(std::string& out) {
        if (take('n')) { out = "std::nullptr_t"; return true; }
        if (take('a')) { out = "auto"; return true; }
        if (take('c')) { out = "decltype(auto)"; return true; }
        if (take('s')) { out = "char16_t"; return true; }
        if (take('i')) { out = "char32_t"; return true; }
        if (take('u')) { out = "char8_t"; return true; }
        if (take('h')) { out = "half"; return true; }
        if (take('p')) { std::string t; if (!parseType(t)) return false; out = t + "..."; return true; }
        if (take('t') || take('T')) {
            std::string e;
            if (!parseExpression(e) || !take('E')) return false;
            out = "decltype(" + e + ")"; return true;
        }
        return false;
    }

    bool parseSubstitution(std::string& out) {
        if (!take('S')) return false;
        struct StdSub { char code; const char* value; };
        static constexpr StdSub stdSubs[] = {
            {'t', "std"}, {'a', "std::allocator"}, {'b', "std::basic_string"},
            {'s', "std::string"}, {'i', "std::istream"}, {'o', "std::ostream"},
            {'d', "std::iostream"},
        };
        for (const StdSub& sub : stdSubs) if (take(sub.code)) { out = sub.value; return true; }

        uint64_t index = 0;
        if (!take('_')) {
            const size_t begin = pos_;
            while (std::isalnum((unsigned char)peek())) {
                const char c = s_[pos_++];
                const unsigned digit = std::isdigit((unsigned char)c) ? c - '0'
                                     : std::isupper((unsigned char)c) ? c - 'A' + 10 : c - 'a' + 10;
                if (digit >= 36 || index > (UINT64_MAX - digit) / 36) return false;
                index = index * 36 + digit;
            }
            if (pos_ == begin || !take('_')) return false;
            ++index;
        }
        if (index >= substitutions_.size()) return false;
        out = substitutions_[(size_t)index];
        return true;
    }

    void remember(const std::string& value) {
        if (value.empty() || substitutions_.size() >= kMaxComponents) return;
        if (std::find(substitutions_.begin(), substitutions_.end(), value) == substitutions_.end())
            substitutions_.push_back(value);
    }

    std::string_view s_;
    size_t pos_ = 0;
    size_t depth_ = 0;
    std::vector<std::string> substitutions_;
    std::string topLabel_;
};

static DemangleResult demangleMicrosoft(std::string_view raw) {
    DemangleResult r;
    r.text.assign(raw);
    r.label = r.text;
    std::string decorated(raw);
    bool importThunk = false;
    if (decorated.starts_with("__imp_?")) {
        decorated.erase(0, 6);
        importThunk = true;
    }
    if (decorated.empty() || decorated[0] != '?') return r;

    // DbgHelp is process-global and must share the same lock as Sym*/StackWalk64.
    std::array<char, kMaxOutput + 1> buffer{};
    std::array<char, kMaxOutput + 1> labelBuffer{};
    constexpr DWORD flags = UNDNAME_NO_ACCESS_SPECIFIERS |
                            UNDNAME_NO_MEMBER_TYPE |
                            UNDNAME_NO_MS_KEYWORDS |
                            UNDNAME_NO_ALLOCATION_MODEL |
                            UNDNAME_NO_ALLOCATION_LANGUAGE |
                            UNDNAME_NO_THISTYPE;
    DWORD n = 0, labelN = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(DbgHelpMutex());
        n = ::UnDecorateSymbolName(decorated.c_str(), buffer.data(), (DWORD)buffer.size(), flags);
        labelN = ::UnDecorateSymbolName(decorated.c_str(), labelBuffer.data(),
                                        (DWORD)labelBuffer.size(), UNDNAME_NAME_ONLY);
    }
    if (!n || n >= buffer.size()) return r;
    std::string text(buffer.data(), n);
    if (text.empty() || text == decorated) return r;
    if (importThunk) text = "import thunk for " + text;
    r.text = std::move(text);
    r.label = labelN && labelN < labelBuffer.size()
            ? std::string(labelBuffer.data(), labelN) : r.text;
    if (importThunk && !r.label.starts_with("import thunk for "))
        r.label = "import thunk for " + r.label;
    r.scheme = DemangleScheme::Microsoft;
    r.complete = true;
    return r;
}

static DemangleResult demangleCDecoration(std::string_view raw) {
    DemangleResult r;
    r.text.assign(raw);
    r.label = r.text;
    std::string_view value = raw;
    bool importThunk = false;
    if (value.starts_with("__imp_")) { value.remove_prefix(6); importThunk = true; }
    if (value.size() < 4) return r;

    size_t at = value.rfind('@');
    if (at == std::string_view::npos || at + 1 >= value.size() || !allDigits(value.substr(at + 1)))
        return r;
    std::string_view name = value.substr(0, at);
    if (!name.empty() && (name.front() == '_' || name.front() == '@')) name.remove_prefix(1);
    if (!name.empty() && name.back() == '@') name.remove_suffix(1); // vectorcall foo@@N
    if (name.empty()) return r;
    for (unsigned char c : name)
        if (!(std::isalnum(c) || c == '_' || c == '$' || c == '?')) return r;

    r.text.assign(name);
    if (importThunk) r.text = "import thunk for " + r.text;
    r.label = r.text;
    r.scheme = DemangleScheme::CDecoration;
    r.complete = true;
    return r;
}

struct CacheState {
    struct Entry { std::string text, label; };
    std::mutex mutex;
    std::unordered_map<std::string, Entry> values;
};

static CacheState& cache() {
    static CacheState state;
    return state;
}

} // namespace

DemangleResult DemangleSymbol(std::string_view raw) {
    DemangleResult unchanged;
    unchanged.text.assign(raw);
    unchanged.label = unchanged.text;
    if (raw.empty() || raw.size() > kMaxInput || raw.find('\0') != std::string_view::npos)
        return unchanged;

    if (raw.starts_with("_Z")) {
        ItaniumParser parser(raw);
        DemangleResult result = parser.run();
        if (result.scheme != DemangleScheme::None) return result;
    }
    if (raw[0] == '?' || raw.starts_with("__imp_?")) {
        DemangleResult result = demangleMicrosoft(raw);
        if (result.scheme != DemangleScheme::None) return result;
    }
    DemangleResult c = demangleCDecoration(raw);
    return c.scheme != DemangleScheme::None ? c : unchanged;
}

std::string DemangleForDisplay(std::string_view raw) {
    if (raw.empty() || raw.size() > kMaxInput) return std::string(raw);
    CacheState& state = cache();
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        auto it = state.values.find(std::string(raw));
        if (it != state.values.end()) return it->second.text;
    }
    DemangleResult parsed = DemangleSymbol(raw);
    std::string value = parsed.text;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.values.size() >= kMaxCache) state.values.clear();
        auto [it, inserted] = state.values.emplace(std::string(raw),
                                                   CacheState::Entry{parsed.text, parsed.label});
        if (!inserted) value = it->second.text;
    }
    return value;
}

std::string DemangleForLabel(std::string_view raw) {
    if (raw.empty() || raw.size() > kMaxInput) return std::string(raw);
    CacheState& state = cache();
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        auto it = state.values.find(std::string(raw));
        if (it != state.values.end()) return it->second.label;
    }
    DemangleResult parsed = DemangleSymbol(raw);
    std::string value = parsed.label;
    {
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.values.size() >= kMaxCache) state.values.clear();
        auto [it, inserted] = state.values.emplace(std::string(raw),
                                                   CacheState::Entry{parsed.text, parsed.label});
        if (!inserted) value = it->second.label;
    }
    return value;
}

size_t DemangleCacheSize() {
    CacheState& state = cache();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.values.size();
}

void ClearDemangleCache() {
    CacheState& state = cache();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.values.clear();
}

} // namespace ds
