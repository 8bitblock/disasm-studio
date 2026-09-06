//
// FuncAnnotate.cpp
// Heuristic per-function annotation engine. See FuncAnnotate.h for the contract.
// Production decoders expose engine-neutral typed operands/register effects.
// Those semantics are authoritative when present; the text parser remains a
// compatibility path for lightweight tests and custom/legacy decoders.
//
#include "FuncAnnotate.h"
#include "ApiDatabase.h"
#include "ApiInfo.h"
#include "NetworkApiCatalog.h"
#include "ValidationApiCatalog.h"
#include "InstructionReference.h"   // instrDataRef / instrImmRef: pure operand parses

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace ds {

const char* NoteKindName(NoteKind k) {
    switch (k) {
        case NoteKind::Prologue:     return "prologue";
        case NoteKind::Epilogue:     return "epilogue";
        case NoteKind::Branch:       return "branch";
        case NoteKind::Loop:         return "loop";
        case NoteKind::Switch:       return "switch";
        case NoteKind::Call:         return "call";
        case NoteKind::IndirectCall: return "indirect call";
        case NoteKind::VirtualCall:  return "virtual call";
        case NoteKind::Vtable:       return "vtable";
        case NoteKind::RetUse:       return "result use";
        case NoteKind::Pattern:      return "pattern";
    }
    return "?";
}

const char* ApiReturnUseKindName(ApiReturnUseKind kind) {
    switch (kind) {
    case ApiReturnUseKind::Unknown:    return "unknown";
    case ApiReturnUseKind::Ignored:    return "ignored";
    case ApiReturnUseKind::Compared:   return "checked";
    case ApiReturnUseKind::Branched:   return "controls branch";
    case ApiReturnUseKind::Stored:     return "stored";
    case ApiReturnUseKind::Propagated: return "propagated";
    case ApiReturnUseKind::Consumed:   return "consumed";
    case ApiReturnUseKind::Returned:   return "returned by caller";
    }
    return "unknown";
}

const char* FunctionReturnKindName(FunctionReturnKind kind) {
    switch (kind) {
    case FunctionReturnKind::Unknown:               return "unknown";
    case FunctionReturnKind::CanonicalBoolean:      return "canonical boolean";
    case FunctionReturnKind::MaterializedCondition: return "materialized condition";
    case FunctionReturnKind::FieldBackedBoolean:    return "field-backed boolean";
    case FunctionReturnKind::ForwardedCall:          return "forwarded call";
    }
    return "unknown";
}

const char* ObjectFieldAccessKindName(ObjectFieldAccessKind kind) {
    switch (kind) {
    case ObjectFieldAccessKind::Read:      return "read";
    case ObjectFieldAccessKind::Write:     return "write";
    case ObjectFieldAccessKind::ReadWrite: return "read/write";
    }
    return "unknown";
}

const char* ApiReplyDecisionKindName(ApiReplyDecisionKind kind) {
    switch (kind) {
    case ApiReplyDecisionKind::DirectComparison: return "direct comparison";
    case ApiReplyDecisionKind::ComparisonCall:   return "comparison call";
    }
    return "unknown";
}

const char* ApiLocalInputDecisionKindName(ApiLocalInputDecisionKind kind) {
    switch (kind) {
    case ApiLocalInputDecisionKind::DirectComparison: return "direct comparison";
    case ApiLocalInputDecisionKind::ComparisonCall:   return "comparison call";
    }
    return "unknown";
}

namespace {

std::string toLower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// Canonical 64-bit register family for any x86/x64 GP register name ("" = not a GP reg).
std::string canonReg(const std::string& tokIn) {
    std::string t = toLower(tokIn);
    static const std::unordered_map<std::string, const char*> kMap = {
        {"rax","rax"},{"eax","rax"},{"ax","rax"},{"al","rax"},{"ah","rax"},
        {"rbx","rbx"},{"ebx","rbx"},{"bx","rbx"},{"bl","rbx"},{"bh","rbx"},
        {"rcx","rcx"},{"ecx","rcx"},{"cx","rcx"},{"cl","rcx"},{"ch","rcx"},
        {"rdx","rdx"},{"edx","rdx"},{"dx","rdx"},{"dl","rdx"},{"dh","rdx"},
        {"rsi","rsi"},{"esi","rsi"},{"si","rsi"},{"sil","rsi"},
        {"rdi","rdi"},{"edi","rdi"},{"di","rdi"},{"dil","rdi"},
        {"rbp","rbp"},{"ebp","rbp"},{"bp","rbp"},{"bpl","rbp"},
        {"rsp","rsp"},{"esp","rsp"},{"sp","rsp"},{"spl","rsp"},
        {"rip","rip"},{"eip","rip"},
    };
    auto it = kMap.find(t);
    if (it != kMap.end()) return it->second;
    // r8..r15 + d/w/b suffix
    if (t.size() >= 2 && t[0] == 'r' && std::isdigit((unsigned char)t[1])) {
        size_t e = t.size();
        if (t.back() == 'd' || t.back() == 'w' || t.back() == 'b') --e;
        if (e >= 2) {
            bool dig = true;
            for (size_t i = 1; i < e; ++i) if (!std::isdigit((unsigned char)t[i])) { dig = false; break; }
            if (dig) {
                int n = std::atoi(t.substr(1, e - 1).c_str());
                if (n >= 8 && n <= 15) return t.substr(0, e);
            }
        }
    }
    return std::string();
}

// The 32-bit-or-64-bit display name of a family for the current bitness.
std::string regDisplay(const std::string& fam, bool x64) {
    if (x64 || fam.empty()) return fam;
    if (fam[0] == 'r' && !std::isdigit((unsigned char)fam[1])) return "e" + fam.substr(1);
    return fam;   // r8.. don't exist on x86-32, leave as-is
}

bool parseImm(const std::string& tokIn, int64_t& out) {
    std::string t = tokIn;
    while (!t.empty() && t.front() == ' ') t.erase(t.begin());
    while (!t.empty() && t.back() == ' ') t.pop_back();
    bool neg = false;
    if (!t.empty() && (t[0] == '-' || t[0] == '+')) { neg = (t[0] == '-'); t.erase(t.begin()); }
    if (t.empty()) return false;
    unsigned long long v = 0;
    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        for (size_t i = 2; i < t.size(); ++i) if (!std::isxdigit((unsigned char)t[i])) return false;
        if (std::sscanf(t.c_str(), "%llx", &v) != 1) return false;
    } else {
        for (char c : t) if (!std::isdigit((unsigned char)c)) return false;
        if (std::sscanf(t.c_str(), "%llu", &v) != 1) return false;
    }
    out = neg ? -(int64_t)v : (int64_t)v;
    return true;
}

void applyApiArgumentKnowledge(const std::string& apiName, bool x64,
                               std::vector<std::string>& arguments) {
    const ApiPrototypeInfo* prototype = FindWindowsApiPrototype(apiName);
    if (!prototype) return;
    for (std::string& argument : arguments) {
        const size_t equal = argument.find('=');
        if (equal == std::string::npos) continue;
        const std::string source = toLower(argument.substr(0, equal));
        size_t index = static_cast<size_t>(-1);
        if (x64) {
            if (source == "rcx") index = 0;
            else if (source == "rdx") index = 1;
            else if (source == "r8") index = 2;
            else if (source == "r9") index = 3;
            else if (source.rfind("arg", 0) == 0 && source.size() > 3) {
                unsigned long parsed = 0;
                const char* first = source.data() + 3;
                const char* last = source.data() + source.size();
                const auto result = std::from_chars(first, last, parsed, 10);
                if (result.ec == std::errc{} && result.ptr == last && parsed)
                    index = static_cast<size_t>(parsed - 1);
            }
        } else if (source.rfind("arg", 0) == 0 && source.size() > 3) {
            unsigned long parsed = 0;
            const char* first = source.data() + 3;
            const char* last = source.data() + source.size();
            const auto result = std::from_chars(first, last, parsed, 10);
            if (result.ec == std::errc{} && result.ptr == last && parsed)
                index = static_cast<size_t>(parsed - 1);
        }
        if (index >= prototype->parameterCount) continue;

        const ApiParameterInfo& parameter = prototype->parameters[index];
        std::string value = argument.substr(equal + 1);
        int64_t immediate = 0;
        if (parameter.valueDomain != ApiValueDomain::None && parseImm(value, immediate)) {
            const std::string symbolic = FormatApiConstant(
                parameter.valueDomain, static_cast<uint64_t>(immediate));
            if (!symbolic.empty()) value = symbolic;
        }
        argument.assign(parameter.name.data(), parameter.name.size());
        argument += '=';
        argument += value;
    }
}

// Top-level comma split of an operand string (x86 brackets never contain commas).
std::vector<std::string> splitOps(const std::string& ops) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= ops.size(); ++i) {
        if (i == ops.size() || ops[i] == ',') {
            std::string t = ops.substr(start, i - start);
            while (!t.empty() && t.front() == ' ') t.erase(t.begin());
            while (!t.empty() && t.back() == ' ') t.pop_back();
            if (!t.empty()) out.push_back(t);
            start = i + 1;
        }
    }
    return out;
}

// Parsed "[base + index*scale + disp]" memory operand.
struct MemOp {
    bool        ok = false;
    std::string base, index;   // canonical families ("" = none)
    int         scale = 1;
    int64_t     disp = 0;
    bool        hasDisp = false;
};

MemOp parseMem(const std::string& op) {
    MemOp m;
    size_t lb = op.find('[');
    if (lb == std::string::npos) return m;
    size_t rb = op.find(']', lb);
    std::string inner = op.substr(lb + 1, (rb == std::string::npos ? op.size() : rb) - lb - 1);
    // Strip a segment prefix ("fs:...").
    if (inner.size() > 3 && inner[2] == ':') inner = inner.substr(3);
    // Tokenize on +/-, keeping the sign.
    size_t i = 0; int sign = 1;
    while (i < inner.size()) {
        while (i < inner.size() && inner[i] == ' ') ++i;
        size_t j = i;
        while (j < inner.size() && inner[j] != '+' && inner[j] != '-') ++j;
        std::string term = inner.substr(i, j - i);
        while (!term.empty() && term.back() == ' ') term.pop_back();
        if (!term.empty()) {
            size_t star = term.find('*');
            if (star != std::string::npos) {                     // index*scale (either order)
                std::string a = term.substr(0, star), b = term.substr(star + 1);
                while (!a.empty() && a.back() == ' ') a.pop_back();
                while (!b.empty() && b.front() == ' ') b.erase(b.begin());
                std::string ra = canonReg(a), rb2 = canonReg(b);
                int64_t sc = 0;
                if (!ra.empty() && parseImm(b, sc))      { m.index = ra; m.scale = (int)sc; }
                else if (!rb2.empty() && parseImm(a, sc)){ m.index = rb2; m.scale = (int)sc; }
            } else {
                std::string r = canonReg(term);
                int64_t v = 0;
                if (!r.empty()) {
                    if (m.base.empty()) m.base = r; else if (m.index.empty()) m.index = r;
                } else if (parseImm(term, v)) {
                    m.disp += sign * v; m.hasDisp = true;
                }
            }
        }
        if (j < inner.size()) sign = (inner[j] == '-') ? -1 : 1;
        i = j + 1;
    }
    m.ok = true;
    return m;
}

std::string compactExpression(std::string value) {
    value = toLower(std::move(value));
    static const char* kDecorators[] = {
        "byte ptr", "word ptr", "dword ptr", "qword ptr", "xmmword ptr"
    };
    for (const char* decorator : kDecorators) {
        const size_t found = value.find(decorator);
        if (found != std::string::npos) value.erase(found, std::strlen(decorator));
    }
    value.erase(std::remove_if(value.begin(), value.end(),
        [](char c) { return std::isspace(static_cast<unsigned char>(c)) != 0; }),
        value.end());
    return value;
}

std::optional<std::string> quotedAsciiPrefix(const std::string& value,
                                             size_t byteCount) {
    if (byteCount > value.size()) return std::nullopt;
    std::string rendered;
    rendered.reserve(byteCount + 2);
    rendered.push_back('"');
    for (size_t index = 0; index < byteCount; ++index) {
        const unsigned char byte = static_cast<unsigned char>(value[index]);
        // The resolver's std::string does not retain an authoritative mapping
        // from display text back to arbitrary multibyte/raw bytes. Abstain when
        // an exact bounded prefix cannot be represented without guessing.
        if (byte < 0x20 || byte > 0x7E) return std::nullopt;
        if (byte == '\\' || byte == '"') rendered.push_back('\\');
        rendered.push_back(static_cast<char>(byte));
    }
    rendered.push_back('"');
    return rendered;
}

struct OutputBufferOrigin {
    std::string expression;
    std::string compact;
    uint64_t referencedAddress = 0;
    bool referencedAddressValid = false;
    MemOp memory;
    std::string pointerRegister;
};

OutputBufferOrigin outputBufferOrigin(const ApiArgumentObservation& argument) {
    OutputBufferOrigin origin;
    // An output-buffer argument is content provenance only when its local
    // producer proved address construction. A bare register may be null,
    // stale, or merely checked as a pointer after the call.
    if (!argument.sourceIsAddress) return origin;
    origin.expression = argument.sourceExpression.empty()
                      ? argument.renderedValue : argument.sourceExpression;
    origin.compact = compactExpression(origin.expression);
    origin.referencedAddress = argument.referencedAddress;
    origin.referencedAddressValid = argument.referencedAddressValid;
    origin.memory = parseMem(origin.expression);
    if (!origin.memory.ok) origin.pointerRegister = canonReg(origin.expression);
    return origin;
}

bool memoryAliasesOutputOrigin(const MemOp& memory,
                               const OutputBufferOrigin& origin,
                               const std::unordered_set<std::string>* pointerAliases = nullptr) {
    if (!memory.ok) return false;
    if (!origin.pointerRegister.empty() &&
        (memory.base == origin.pointerRegister || memory.index == origin.pointerRegister))
        return true;
    if (pointerAliases &&
        ((!memory.base.empty() && pointerAliases->count(memory.base)) ||
         (!memory.index.empty() && pointerAliases->count(memory.index))))
        return true;
    if (!origin.memory.ok || memory.base != origin.memory.base) return false;
    if (!origin.memory.index.empty() && memory.index != origin.memory.index) return false;
    const int64_t originDisp = origin.memory.hasDisp ? origin.memory.disp : 0;
    const int64_t candidateDisp = memory.hasDisp ? memory.disp : 0;
    const int64_t delta = candidateDisp - originDisp;
    // A local bounded response window.  Negative offsets point before the
    // recovered buffer and are not accepted as aliases.
    return delta >= 0 && delta <= 512;
}

bool argumentAliasesOutputOrigin(const ApiArgumentObservation& argument,
                                 const OutputBufferOrigin& origin) {
    if (origin.referencedAddressValid && argument.referencedAddressValid &&
        origin.referencedAddress == argument.referencedAddress)
        return true;
    const std::string expression = argument.sourceExpression.empty()
                                 ? argument.renderedValue : argument.sourceExpression;
    const std::string compact = compactExpression(expression);
    if (!origin.compact.empty() && compact == origin.compact) return true;
    const std::string reg = canonReg(expression);
    if (!origin.pointerRegister.empty() && reg == origin.pointerRegister) return true;
    return memoryAliasesOutputOrigin(parseMem(expression), origin);
}

// Local-input decisions deliberately use exact origin equality rather than the
// reply pass's bounded +512-byte window. Without a recovered capacity, treating
// [rbp-0x40] as an alias of [rbp-0x80] can join two unrelated local buffers.
bool memoryExactlyAliasesOutputOrigin(const MemOp& memory,
                                      const OutputBufferOrigin& origin) {
    if (!memory.ok || !origin.memory.ok) return false;
    const int64_t memoryDisp = memory.hasDisp ? memory.disp : 0;
    const int64_t originDisp = origin.memory.hasDisp ? origin.memory.disp : 0;
    return memory.base == origin.memory.base &&
           memory.index == origin.memory.index &&
           memory.scale == origin.memory.scale &&
           memoryDisp == originDisp;
}

bool argumentExactlyAliasesOutputOrigin(const ApiArgumentObservation& argument,
                                        const OutputBufferOrigin& origin) {
    if (origin.referencedAddressValid && argument.referencedAddressValid)
        return origin.referencedAddress == argument.referencedAddress;
    if (!argument.sourceIsAddress) return false;
    const std::string expression = argument.sourceExpression.empty()
                                 ? argument.renderedValue : argument.sourceExpression;
    const std::string compact = compactExpression(expression);
    if (!origin.compact.empty() && compact == origin.compact) return true;
    const std::string reg = canonReg(expression);
    if (!origin.pointerRegister.empty() && reg == origin.pointerRegister) return true;
    return memoryExactlyAliasesOutputOrigin(parseMem(expression), origin);
}

std::pair<std::string_view, std::string_view> splitQualifiedApiName(
        const std::string& qualified) {
    size_t separator = qualified.rfind('!');
    if (separator == std::string::npos) separator = qualified.rfind('.');
    if (separator == std::string::npos || separator == 0 ||
        separator + 1 >= qualified.size())
        return {};
    return { std::string_view(qualified).substr(0, separator),
             std::string_view(qualified).substr(separator + 1) };
}

std::optional<ValidationApiMatch> exactValidationApiForName(
        const std::string& qualified) {
    const auto [dll, symbol] = splitQualifiedApiName(qualified);
    if (dll.empty() || symbol.empty()) return std::nullopt;
    return LookupValidationApi(dll, symbol);
}

bool validationEncodingsCompatible(ValidationDataEncoding input,
                                   ValidationDataEncoding comparator) {
    return input == comparator || comparator == ValidationDataEncoding::Bytes;
}

// All canonical register families appearing anywhere in a text fragment.
void regsInText(const std::string& s, std::vector<std::string>& out) {
    size_t i = 0;
    while (i < s.size()) {
        if (std::isalnum((unsigned char)s[i])) {
            size_t j = i;
            while (j < s.size() && std::isalnum((unsigned char)s[j])) ++j;
            std::string fam = canonReg(s.substr(i, j - i));
            if (!fam.empty() && fam != "rip") out.push_back(fam);
            i = j;
        } else ++i;
    }
}

// Per-instruction register reads/writes. Production decoder semantics are used
// first; formatted-text inference is retained for legacy/mock instructions.
struct RW {
    std::vector<std::string> reads, writes;
    bool zeroIdiom = false;       // xor r,r / sub r,r: writes without reading
};

void addRegisterFamily(std::vector<std::string>& registers,
                       const std::string& decodedName) {
    const std::string family = canonReg(decodedName);
    if (family.empty() || family == "rip") return;
    if (std::find(registers.begin(), registers.end(), family) == registers.end())
        registers.push_back(family);
}

bool typedZeroIdiom(const Instruction& in, std::string& destination) {
    if (in.mnemonic != "xor" && in.mnemonic != "sub") return false;
    if (in.typedOperands.size() < 2 ||
        in.typedOperands[0].kind != OperandKind::Register ||
        in.typedOperands[1].kind != OperandKind::Register)
        return false;
    const std::string first = canonReg(in.typedOperands[0].registerName);
    const std::string second = canonReg(in.typedOperands[1].registerName);
    if (first.empty() || first != second) return false;
    destination = first;
    return true;
}

bool isWriteFirstOp(const std::string& m) {
    return m == "mov" || m == "movzx" || m == "movsx" || m == "movsxd" || m == "movabs" ||
           m == "lea" || m == "pop" || m.rfind("set", 0) == 0 || m.rfind("cmov", 0) == 0 ||
           m == "bswap";
}
bool isRmwFirstOp(const std::string& m) {
    return m == "add" || m == "sub" || m == "adc" || m == "sbb" || m == "and" || m == "or" ||
           m == "xor" || m == "shl" || m == "sal" || m == "shr" || m == "sar" || m == "rol" ||
           m == "ror" || m == "inc" || m == "dec" || m == "neg" || m == "not" || m == "imul" ||
           m == "xadd" || m == "btc" || m == "bts" || m == "btr";
}

RW classifyRW(const Instruction& in) {
    RW rw;
    const std::string& m = in.mnemonic;
    std::vector<std::string> ops = splitOps(in.operands);
    auto addReads = [&](const std::string& text) { regsInText(text, rw.reads); };

    const bool haveDecodedSemantics = !in.typedOperands.empty() ||
                                      !in.registersRead.empty() ||
                                      !in.registersWritten.empty();
    if (haveDecodedSemantics) {
        for (const std::string& reg : in.registersRead)
            addRegisterFamily(rw.reads, reg);
        for (const std::string& reg : in.registersWritten)
            addRegisterFamily(rw.writes, reg);

        // Operand access fills explicit effects when a backend does not publish
        // a complete register set. Memory base and index registers are reads
        // even when the memory itself is only written: they form its address.
        for (const TypedOperand& operand : in.typedOperands) {
            if (operand.kind == OperandKind::Register) {
                if (OperandReads(operand.access))
                    addRegisterFamily(rw.reads, operand.registerName);
                if (OperandWrites(operand.access))
                    addRegisterFamily(rw.writes, operand.registerName);
            } else if (operand.kind == OperandKind::Memory) {
                addRegisterFamily(rw.reads, operand.baseRegister);
                addRegisterFamily(rw.reads, operand.indexRegister);
            }
        }

        // Calls retain the established ABI model: decoder metadata describes
        // the encoded target/stack effects, not every volatile register the
        // unknown callee may overwrite.
        if (InstructionIsCall(in)) {
            static const char* kVolatile[] = {
                "rax", "rcx", "rdx", "r8", "r9", "r10", "r11"
            };
            for (const char* reg : kVolatile) addRegisterFamily(rw.writes, reg);
            return rw;
        }

        // Decoders correctly report xor/sub inputs as reads, but for bounded
        // provenance these dependency-breaking forms overwrite the old value.
        std::string zeroDestination;
        if (typedZeroIdiom(in, zeroDestination)) {
            rw.reads.erase(std::remove(rw.reads.begin(), rw.reads.end(),
                                       zeroDestination), rw.reads.end());
            addRegisterFamily(rw.writes, zeroDestination);
            rw.zeroIdiom = true;
        }
        return rw;
    }

    if (InstructionIsCall(in)) {
        // Volatile registers clobbered by the callee (we don't model callee reads).
        rw.writes = { "rax", "rcx", "rdx", "r8", "r9", "r10", "r11" };
        for (const auto& o : ops) addReads(o);   // computed-target registers are read
        return rw;
    }
    if (m == "push" || m == "cmp" || m == "test" || m == "ret" || m.rfind("j", 0) == 0) {
        for (const auto& o : ops) addReads(o);
        return rw;
    }
    if (m == "pop" && !ops.empty()) {
        std::string r = canonReg(ops[0]);
        if (!r.empty()) rw.writes.push_back(r); else addReads(ops[0]);
        return rw;
    }
    if (m == "xchg" && ops.size() == 2) {
        for (const auto& o : ops) { addReads(o); std::string r = canonReg(o); if (!r.empty()) rw.writes.push_back(r); }
        return rw;
    }
    if (m == "mul" || m == "div" || m == "idiv" || (m == "imul" && ops.size() == 1)) {
        for (const auto& o : ops) addReads(o);
        rw.reads.push_back("rax"); rw.writes.push_back("rax"); rw.writes.push_back("rdx");
        return rw;
    }
    if (ops.empty()) return rw;

    bool dstIsMem = ops[0].find('[') != std::string::npos;
    std::string dstReg = dstIsMem ? std::string() : canonReg(ops[0]);
    // Registers used inside a memory destination are reads (address computation).
    if (dstIsMem) addReads(ops[0]);
    for (size_t i = 1; i < ops.size(); ++i) addReads(ops[i]);

    if (!dstReg.empty()) {
        bool zero = (m == "xor" || m == "sub") && ops.size() == 2 && canonReg(ops[1]) == dstReg;
        if (zero) { rw.writes.push_back(dstReg); rw.zeroIdiom = true; return rw; }
        if (isWriteFirstOp(m))      { rw.writes.push_back(dstReg); }
        else if (isRmwFirstOp(m))   { rw.reads.push_back(dstReg); rw.writes.push_back(dstReg); }
        else                        { rw.reads.push_back(dstReg); }   // unknown: assume read
    }
    return rw;
}

// Does this instruction WRITE its first-operand memory? (mirrors instrDataAccess)
bool writesMemFirstOp(const Instruction& in) {
    if (!in.typedOperands.empty()) {
        const TypedOperand& first = in.typedOperands.front();
        if (first.kind != OperandKind::Memory) return false;
        if (first.access != OperandAccess::None) return OperandWrites(first.access);
        // An older/partial producer may know that this is memory without
        // knowing its access. Preserve the bounded text fallback in that case.
    }
    const std::string& m = in.mnemonic;
    std::vector<std::string> ops = splitOps(in.operands);
    if (ops.empty() || ops[0].find('[') == std::string::npos) return false;
    if (m == "cmp" || m == "test" || m == "push" || m == "call" || m == "jmp" || m == "lea") return false;
    if (ops.size() == 1)
        return m == "pop" || m == "inc" || m == "dec" || m == "neg" || m == "not" || m.rfind("set", 0) == 0;
    return true;
}

const char* jccExprOp(const std::string& m, bool& isSigned, bool& isUnsigned) {
    isSigned = isUnsigned = false;
    if (m == "je"  || m == "jz")  return "==";
    if (m == "jne" || m == "jnz") return "!=";
    if (m == "jg"  || m == "jnle"){ isSigned = true;   return ">";  }
    if (m == "jge" || m == "jnl") { isSigned = true;   return ">="; }
    if (m == "jl"  || m == "jnge"){ isSigned = true;   return "<";  }
    if (m == "jle" || m == "jng") { isSigned = true;   return "<="; }
    if (m == "ja"  || m == "jnbe"){ isUnsigned = true; return ">";  }
    if (m == "jae" || m == "jnb") { isUnsigned = true; return ">="; }
    if (m == "jb"  || m == "jnae"){ isUnsigned = true; return "<";  }
    if (m == "jbe" || m == "jna") { isUnsigned = true; return "<="; }
    if (m == "js")  return "s";     // sign set / clear handled specially
    if (m == "jns") return "ns";
    return nullptr;
}

bool isCondJump(const Instruction& in) {
    if (in.flow.kind != FlowKind::None)
        return in.flow.kind == FlowKind::ConditionalBranch && HasBranchTarget(in);
    return in.isBranch && !in.isCall && !in.isRet && HasBranchTarget(in) &&
           !in.mnemonic.empty() && in.mnemonic != "jmp" && in.mnemonic[0] == 'j';
}

bool isFlagSetter(const std::string& m) {
    return m == "cmp" || m == "test" || m == "add" || m == "sub" || m == "and" || m == "or" ||
           m == "xor" || m == "inc" || m == "dec" || m == "neg" || m == "shl" || m == "shr" ||
           m == "sar" || m == "sal" || m == "imul" || m == "adc" || m == "sbb" || m == "bt";
}

bool isFlagSetter(const Instruction& in) {
    return in.flagsWritten != 0 || isFlagSetter(in.mnemonic);
}

bool nameLooksLikeCompare(const std::string& nm) {
    std::string n = toLower(nm);
    return n.find("strcmp") != std::string::npos || n.find("stricmp") != std::string::npos ||
           n.find("memcmp") != std::string::npos || n.find("wcscmp") != std::string::npos ||
           n.find("lstrcmp") != std::string::npos || n.find("comparestring") != std::string::npos ||
           n.find("strncmp") != std::string::npos || n.find("cmpi") != std::string::npos;
}

std::optional<NetworkApiMatch> exactNetworkApiForName(const std::string& qualified) {
    size_t separator = qualified.rfind('!');
    if (separator == std::string::npos) separator = qualified.rfind('.');
    if (separator == std::string::npos || separator == 0 ||
        separator + 1 >= qualified.size())
        return std::nullopt;
    return LookupNetworkApi(std::string_view(qualified).substr(0, separator),
                            std::string_view(qualified).substr(separator + 1));
}

struct EqualityCompareContract {
    int64_t equalityResult = 0;
    std::string canonicalName;
};

std::optional<EqualityCompareContract> exactEqualityCompareForName(
    const std::string& qualified) {
    size_t separator = qualified.find_last_of("!.");
    std::string name = separator == std::string::npos
                     ? qualified : qualified.substr(separator + 1);
    name = toLower(name);
    static const char* kImportPrefixes[] = {
        "__imp__", "__imp_", "_imp__", "_imp_", "imp_"
    };
    bool stripped = true;
    while (stripped) {
        stripped = false;
        for (const char* prefix : kImportPrefixes) {
            const size_t n = std::strlen(prefix);
            if (name.rfind(prefix, 0) == 0) {
                name.erase(0, n);
                stripped = true;
                break;
            }
        }
    }
    const size_t at = name.rfind('@');
    if (at != std::string::npos && at + 1 < name.size() &&
        std::all_of(name.begin() + static_cast<std::ptrdiff_t>(at + 1), name.end(),
                    [](char c) { return c >= '0' && c <= '9'; }))
        name.resize(at);

    static const char* kZeroMeansEqual[] = {
        "strcmp", "strncmp", "stricmp", "strnicmp", "_stricmp", "_strnicmp",
        "wcscmp", "wcsncmp", "wcsicmp", "wcsnicmp", "_wcsicmp", "_wcsnicmp",
        "memcmp", "lstrcmpa", "lstrcmpw", "lstrcmpia", "lstrcmpiw"
    };
    for (const char* candidate : kZeroMeansEqual)
        if (name == candidate) return EqualityCompareContract{ 0, candidate };
    if (name == "comparestringa" || name == "comparestringw" ||
        name == "comparestringex")
        return EqualityCompareContract{ 2, name }; // CSTR_EQUAL
    return std::nullopt;
}

std::string instructionText(const Instruction& instruction) {
    return instruction.operands.empty()
         ? instruction.mnemonic
         : instruction.mnemonic + " " + instruction.operands;
}

std::string vaHex(uint64_t va) {
    char b[24]; std::snprintf(b, sizeof(b), "0x%llX", (unsigned long long)va);
    return b;
}

uint16_t registerWidthBits(const std::string& spelling, bool x64) {
    const std::string value = toLower(spelling);
    if (value.empty()) return 0;
    if (value == "al" || value == "ah" || value == "bl" || value == "bh" ||
        value == "cl" || value == "ch" || value == "dl" || value == "dh" ||
        value == "sil" || value == "dil" || value == "bpl" || value == "spl")
        return 8;
    if (value == "ax" || value == "bx" || value == "cx" || value == "dx" ||
        value == "si" || value == "di" || value == "bp" || value == "sp")
        return 16;
    if (value == "eax" || value == "ebx" || value == "ecx" || value == "edx" ||
        value == "esi" || value == "edi" || value == "ebp" || value == "esp" ||
        value == "eip")
        return 32;
    if (value == "rax" || value == "rbx" || value == "rcx" || value == "rdx" ||
        value == "rsi" || value == "rdi" || value == "rbp" || value == "rsp" ||
        value == "rip")
        return x64 ? 64 : 32;
    if (value.size() >= 2 && value[0] == 'r' &&
        std::isdigit(static_cast<unsigned char>(value[1]))) {
        if (value.back() == 'b') return 8;
        if (value.back() == 'w') return 16;
        if (value.back() == 'd') return 32;
        return 64;
    }
    return 0;
}

bool isHighByteRegister(const std::string& spelling) {
    const std::string value = toLower(spelling);
    return value == "ah" || value == "bh" || value == "ch" || value == "dh";
}

uint16_t textMemoryWidthBits(const std::string& operand) {
    const std::string value = toLower(operand);
    if (value.find("byte ptr") != std::string::npos) return 8;
    if (value.find("word ptr") != std::string::npos &&
        value.find("dword ptr") == std::string::npos &&
        value.find("qword ptr") == std::string::npos &&
        value.find("xmmword ptr") == std::string::npos)
        return 16;
    if (value.find("dword ptr") != std::string::npos) return 32;
    if (value.find("qword ptr") != std::string::npos) return 64;
    if (value.find("xmmword ptr") != std::string::npos) return 128;
    return 0;
}

bool checkedAddSigned(int64_t left, int64_t right, int64_t& result) {
    if (right > 0 && left > (std::numeric_limits<int64_t>::max)() - right)
        return false;
    if (right < 0 && left < (std::numeric_limits<int64_t>::min)() - right)
        return false;
    result = left + right;
    return true;
}

// One flat, address-ordered view over the CFG with block boundaries kept.
struct FlatInsn {
    const Instruction* in;
    int block;        // owning block index
    int idxInBlock;
};

} // namespace

FuncAnnotations AnnotateFunction(const ControlFlowGraph& g, const AnnotateOptions& opt) {
    FuncAnnotations out;
    out.fieldAccessAnalysisAttempted = true;
    out.fieldAccessesComplete = false;
    out.directCallFormalBindingAnalysisAttempted = true;
    out.directCallFormalBindingsComplete = false;
    out.returnObservation.analysisAttempted = true;
    out.returnObservation.complete = false;
    out.complete = g.complete;
    out.incompleteReason = g.incompleteReason;
    out.chunks = opt.chunks;
    out.ownershipTruncated = opt.ownershipTruncated;
    out.seedKind = opt.seedKind;
    out.boundaryConfidence = opt.boundaryConfidence;
    auto metadataSummary = [&]() {
        std::string summary = std::string(FunctionBoundaryConfidenceName(out.boundaryConfidence)) +
                              " boundary (" + FunctionSeedKindName(out.seedKind) + " seed)";
        if (out.chunks.size() > 1)
            summary += " · " + std::to_string(out.chunks.size()) + " chunks";
        if (out.ownershipTruncated) summary += " · ownership truncated";
        if (!out.complete)
            summary += " · CFG incomplete" +
                       (out.incompleteReason.empty() ? std::string()
                                                    : ": " + out.incompleteReason);
        return summary;
    };
    out.summary = metadataSummary();
    if (g.blocks.empty()) {
        out.fieldAccessIncompleteReason = "CFG has no basic blocks";
        out.directCallFormalBindingIncompleteReason = "CFG has no basic blocks";
        out.returnObservation.incompleteReason = "CFG has no basic blocks";
        return out;
    }
    const bool x64 = opt.x64;

    auto nameFor   = [&](uint64_t va) { return opt.nameFor ? opt.nameFor(va) : std::string(); };
    auto stringFor = [&](uint64_t va) { return opt.stringFor ? opt.stringFor(va) : std::string(); };

    // Block order by start address (BuildCFG emits them sorted, but don't rely on it).
    std::vector<int> order(g.blocks.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = (int)i;
    std::sort(order.begin(), order.end(),
              [&](int a, int b) { return g.blocks[a].start < g.blocks[b].start; });

    std::vector<FlatInsn> flat;
    for (int bi : order)
        for (size_t k = 0; k < g.blocks[bi].insns.size(); ++k)
            flat.push_back({ &g.blocks[bi].insns[k], bi, (int)k });
    if (flat.empty()) {
        out.fieldAccessIncompleteReason = "CFG has no decoded instructions";
        out.directCallFormalBindingIncompleteReason =
            "CFG has no decoded instructions";
        out.returnObservation.incompleteReason = "CFG has no decoded instructions";
        return out;
    }

    auto note = [&](uint64_t va, NoteKind kind, std::string text, std::string evidence, float conf) {
        FnNote n; n.va = va; n.sourceValid = true; n.kind = kind; n.text = std::move(text);
        n.evidence = std::move(evidence); n.confidence = conf;
        out.notes.push_back(std::move(n));
    };
    auto functionNote = [&](NoteKind kind, std::string text,
                            std::string evidence, float conf) {
        FnNote n; n.sourceValid = false; n.kind = kind; n.text = std::move(text);
        n.evidence = std::move(evidence); n.confidence = conf;
        out.notes.push_back(std::move(n));
    };

    // The display name a call resolves to: relative target, or the IAT slot it
    // reads through ("call [rip+x]"), or "" for register-indirect.
    auto callName = [&](const Instruction& in) -> std::string {
        if (HasBranchTarget(in)) {
            std::string n = nameFor(in.branchTarget);
            return n.empty() ? ("sub_" + vaHex(in.branchTarget).substr(2)) : n;
        }
        uint64_t slot = 0;
        if (TryGetInstrDataRef(in, slot)) {
            std::string n = nameFor(slot);
            if (!n.empty()) return n;
        }
        return std::string();
    };

    // ---- 1) Prologue / epilogue / frame ------------------------------------
    {
        const BasicBlock& entry = g.blocks[order[0]];
        static const std::set<std::string> kCalleeSaved64 = { "rbx","rsi","rdi","rbp","r12","r13","r14","r15" };
        size_t scan = std::min<size_t>(entry.insns.size(), 12);
        bool sawPushBp = false;
        for (size_t k = 0; k < scan; ++k) {
            const Instruction& in = entry.insns[k];
            const std::string& m = in.mnemonic;
            std::vector<std::string> ops = splitOps(in.operands);
            if (m == "push" && ops.size() == 1) {
                std::string r = canonReg(ops[0]);
                if (r == "rbp") {
                    sawPushBp = true;
                    note(in.address, NoteKind::Prologue, "prologue: save caller's frame pointer",
                         "push " + regDisplay("rbp", x64) + " at function entry", 0.9f);
                } else if (kCalleeSaved64.count(r)) {
                    note(in.address, NoteKind::Prologue, "prologue: save callee-saved " + regDisplay(r, x64),
                         "push of a callee-saved register near function entry", 0.8f);
                }
            } else if (m == "mov" && ops.size() == 2 && canonReg(ops[0]) == "rbp" && canonReg(ops[1]) == "rsp") {
                out.hasFramePointer = true;
                note(in.address, NoteKind::Prologue, "prologue: establish frame pointer",
                     std::string("mov ") + regDisplay("rbp", x64) + ", " + regDisplay("rsp", x64) +
                     (sawPushBp ? " after push — canonical frame setup" : ""), 0.9f);
            } else if (m == "sub" && ops.size() == 2 && canonReg(ops[0]) == "rsp") {
                int64_t n = 0;
                if (parseImm(ops[1], n) && n > 0) {
                    out.frameBytes = (uint32_t)n;
                    note(in.address, NoteKind::Prologue,
                         "prologue: reserve " + vaHex((uint64_t)n) + " bytes of stack frame (locals/spill)",
                         "sub " + regDisplay("rsp", x64) + ", " + vaHex((uint64_t)n) + " near function entry", 0.9f);
                }
            }
        }
        // Epilogues: look just before each ret.
        for (int bi : order) {
            const BasicBlock& b = g.blocks[bi];
            if (!b.isReturn || b.insns.empty()) continue;
            for (size_t k = b.insns.size() >= 4 ? b.insns.size() - 4 : 0; k + 1 < b.insns.size(); ++k) {
                const Instruction& in = b.insns[k];
                std::vector<std::string> ops = splitOps(in.operands);
                if (in.mnemonic == "leave")
                    note(in.address, NoteKind::Epilogue, "epilogue: tear down frame (mov rsp,rbp; pop rbp)",
                         "leave immediately before ret", 0.9f);
                else if (in.mnemonic == "add" && ops.size() == 2 && canonReg(ops[0]) == "rsp")
                    note(in.address, NoteKind::Epilogue, "epilogue: release stack frame",
                         "add " + regDisplay("rsp", x64) + " just before ret", 0.85f);
                else if (in.mnemonic == "pop" && ops.size() == 1 && canonReg(ops[0]) == "rbp")
                    note(in.address, NoteKind::Epilogue, "epilogue: restore caller's frame pointer",
                         "pop " + regDisplay("rbp", x64) + " just before ret", 0.85f);
            }
        }
    }

    // ---- 2) Register lifetimes + read-before-write argument evidence -------
    struct Life {
        uint64_t first = 0, last = 0;
        int reads = 0, writes = 0;
        bool firstValid = false;
        bool writtenFirst = false;
    };
    std::map<std::string, Life> life;
    std::set<std::string> writtenEver;
    struct ArgEvidence { uint64_t va = 0; bool asBase = false; };
    std::map<std::string, ArgEvidence> regArgEvidence;   // arg-reg family -> first pre-write read
    std::map<std::string, std::set<int64_t>> fieldOffsets; // reg used as struct base -> field disps

    static const char* kArgRegs64[] = { "rcx", "rdx", "r8", "r9" };
    for (const FlatInsn& f : flat) {
        const Instruction& in = *f.in;
        RW rw = classifyRW(in);
        for (const std::string& r : rw.reads) {
            if (r == "rsp") continue;
            Life& L = life[r];
            if (!L.firstValid) {
                L.first = in.address; L.firstValid = true; L.writtenFirst = false;
            }
            L.last = in.address; ++L.reads;
            if (!writtenEver.count(r)) {
                bool isArgReg = false;
                if (x64) { for (const char* a : kArgRegs64) if (r == a) isArgReg = true; }
                else     { isArgReg = (r == "rcx" || r == "rdx"); }   // ecx/edx: thiscall/fastcall hints
                if (isArgReg && !regArgEvidence.count(r)) {
                    MemOp mo = parseMem(in.operands);
                    regArgEvidence[r] = { in.address, mo.ok && (mo.base == r || mo.index == r) };
                }
            }
            // Struct/this-pointer field access: [reg + smallDisp]
            MemOp mo = parseMem(in.operands);
            if (mo.ok && mo.base == r && r != "rbp" && r != "rsp" && mo.hasDisp && mo.disp >= 0 && mo.disp < 0x1000)
                fieldOffsets[r].insert(mo.disp);
        }
        for (const std::string& r : rw.writes) {
            if (r == "rsp") continue;
            Life& L = life[r];
            if (!L.firstValid) {
                L.first = in.address; L.firstValid = true; L.writtenFirst = true;
            }
            L.last = in.address; ++L.writes;
            writtenEver.insert(r);
        }
    }
    for (auto& [r, L] : life) {
        RegLifetime rl; rl.reg = r; rl.firstVA = L.first; rl.lastVA = L.last;
        rl.reads = L.reads; rl.writes = L.writes;
        out.regs.push_back(std::move(rl));
    }
    std::sort(out.regs.begin(), out.regs.end(),
              [](const RegLifetime& a, const RegLifetime& b) { return a.firstVA < b.firstVA; });

    // ---- 3) Stack frame slots (locals + stack args) -------------------------
    {
        std::map<std::pair<std::string, int64_t>, StackSlot> slots;
        for (const FlatInsn& f : flat) {
            const Instruction& in = *f.in;
            MemOp mo = parseMem(in.operands);
            if (!mo.ok || mo.base.empty()) continue;
            bool viaBp = mo.base == "rbp", viaSp = mo.base == "rsp";
            if (!viaBp && !viaSp) continue;
            if (in.mnemonic == "lea" && splitOps(in.operands).size() == 2) {
                // lea of a frame slot = address taken; still record the slot.
            }
            bool isArg = false; bool isLocal = false;
            if (viaBp) {
                if (mo.disp < 0) isLocal = true;
                else if (mo.disp >= (x64 ? 0x10 : 8)) isArg = true;
            } else if (viaSp) {
                if (mo.disp >= 0 && out.frameBytes && (uint64_t)mo.disp < out.frameBytes) isLocal = true;
                else if (out.frameBytes && (uint64_t)mo.disp >= out.frameBytes + (x64 ? 8u : 4u)) isArg = true;
                else if (!out.frameBytes) continue;   // no frame info: rsp offsets are ambiguous
            }
            if (!isArg && !isLocal) continue;
            auto key = std::make_pair(regDisplay(mo.base, x64), mo.disp);
            StackSlot& s = slots[key];
            if (s.name.empty()) {
                s.base = key.first; s.offset = mo.disp; s.isArg = isArg;
                char nm[32];
                if (isArg) {
                    int64_t argBase = viaBp ? (x64 ? 0x10 : 8) : (int64_t)out.frameBytes + (x64 ? 8 : 4);
                    std::snprintf(nm, sizeof(nm), "arg_%llX", (unsigned long long)(mo.disp - argBase));
                } else {
                    std::snprintf(nm, sizeof(nm), viaBp ? "var_%llX" : "var_s%llX",
                                  (unsigned long long)(viaBp ? -mo.disp : mo.disp));
                }
                s.name = nm;
            }
            if (writesMemFirstOp(in)) ++s.writes; else ++s.reads;
        }
        for (auto& [k, s] : slots) out.stack.push_back(std::move(s));
        std::sort(out.stack.begin(), out.stack.end(), [](const StackSlot& a, const StackSlot& b) {
            if (a.isArg != b.isArg) return !a.isArg;
            return a.offset < b.offset;
        });
    }

    // ---- 4) Calling convention + arguments ----------------------------------
    {
        int stackArgs = 0;
        for (const StackSlot& s : out.stack) if (s.isArg) ++stackArgs;
        if (x64) {
            // Count the contiguous run of arg registers with pre-write reads.
            int nreg = 0;
            for (const char* a : kArgRegs64) { if (regArgEvidence.count(a)) ++nreg; else break; }
            int loose = (int)regArgEvidence.size();   // non-contiguous reads still count as evidence
            if (loose > nreg) nreg = loose;
            if (nreg > 0 || stackArgs > 0) {
                out.convention = "Microsoft x64 (rcx, rdx, r8, r9)";
                out.convConfidence = 0.65f;
                std::string ev;
                for (auto& [r, e] : regArgEvidence) {
                    ev += ev.empty() ? "reads " : ", ";
                    ev += r + " at " + vaHex(e.va) + " before writing it";
                }
                if (stackArgs) ev += (ev.empty() ? "accesses " : "; plus ") +
                                     std::to_string(stackArgs) + " stack slot(s) above the return address";
                out.convEvidence = ev + " (register-usage heuristic; arg forwarding through calls not modelled)";
            } else {
                out.convention = "Microsoft x64 (assumed; no argument use observed)";
                out.convConfidence = 0.3f;
                out.convEvidence = "no argument register or stack-arg reads seen before they are overwritten";
            }
            int argn = 1;
            for (const char* a : kArgRegs64) {
                auto it = regArgEvidence.find(a);
                if (it == regArgEvidence.end()) { ++argn; continue; }
                std::string line = "arg" + std::to_string(argn) + " in " + a;
                auto fo = fieldOffsets.find(a);
                if (fo != fieldOffsets.end() && !fo->second.empty()) {
                    line += " — used as object/struct pointer (fields";
                    int shown = 0;
                    for (int64_t d : fo->second) { if (shown++ == 4) { line += ", ..."; break; } line += " +" + vaHex((uint64_t)d); }
                    line += ")";
                } else if (it->second.asBase) {
                    line += " — used as a pointer (memory base)";
                } else {
                    line += " — read at " + vaHex(it->second.va);
                }
                out.args.push_back(line);
                ++argn;
            }
            for (const StackSlot& s : out.stack)
                if (s.isArg) out.args.push_back("stack arg " + s.name + " at [" + s.base +
                                                (s.offset >= 0 ? "+" : "") + vaHex((uint64_t)s.offset) + "]");
        } else {
            // x86-32: ret imm is strong; ecx-before-write + field use suggests thiscall.
            uint32_t retImm = 0;
            for (int bi : order) {
                const BasicBlock& b = g.blocks[bi];
                if (!b.isReturn || b.insns.empty()) continue;
                const Instruction& r = BlockTransferInstruction(b);
                if (InstructionIsReturn(r) && !r.operands.empty()) { int64_t v = 0; if (parseImm(r.operands, v) && v > 0) retImm = (uint32_t)v; }
            }
            bool ecxThis = regArgEvidence.count("rcx") &&
                           fieldOffsets.count("rcx") && !fieldOffsets["rcx"].empty();
            if (retImm) {
                out.convention = ecxThis ? "thiscall? (this in ecx, ret " + vaHex(retImm) + ")"
                                         : "stdcall (ret " + vaHex(retImm) + ")";
                out.convConfidence = ecxThis ? 0.6f : 0.85f;
                out.convEvidence = "ret " + vaHex(retImm) + " pops " + std::to_string(retImm / 4) +
                                   " stack argument(s) — callee-cleaned" +
                                   (ecxThis ? "; ecx read before write and used for field access" : "");
            } else if (ecxThis) {
                out.convention = "thiscall/fastcall? (ecx used before write)";
                out.convConfidence = 0.5f;
                out.convEvidence = "ecx read before any write and dereferenced with field offsets";
            } else if (stackArgs > 0) {
                out.convention = "cdecl (caller-cleaned stack args)";
                out.convConfidence = 0.5f;
                out.convEvidence = std::to_string(stackArgs) + " [ebp+N] argument slot(s) read; plain ret (caller cleans)";
            } else {
                out.convention = "cdecl (assumed; no argument use observed)";
                out.convConfidence = 0.3f;
                out.convEvidence = "no stack-argument reads seen";
            }
            if (ecxThis) {
                std::string line = "this in ecx — fields";
                int shown = 0;
                for (int64_t d : fieldOffsets["rcx"]) { if (shown++ == 4) { line += ", ..."; break; } line += " +" + vaHex((uint64_t)d); }
                out.args.push_back(line);
            }
            for (const StackSlot& s : out.stack)
                if (s.isArg) out.args.push_back(s.name + " at [ebp+" + vaHex((uint64_t)s.offset) + "]");
        }
    }

    // ---- 5) Loops (back edges by address order) -----------------------------
    struct LoopInfo { int header, latch; uint64_t lo, hi; };
    std::vector<LoopInfo> loops;
    std::unordered_set<uint64_t> loopTermVAs;   // latch terminators that got a loop note
    for (int bi : order) {
        const BasicBlock& b = g.blocks[bi];
        if (b.insns.empty()) continue;
        for (size_t s : b.succ) {
            if (s >= g.blocks.size()) continue;
            const BasicBlock& h = g.blocks[s];
            if (h.start > b.start || h.insns.empty()) continue;   // forward edge
            // Back edge b -> h. Treat [h.start, b.end) as the loop body (approximate).
            loops.push_back({ (int)s, bi, h.start, b.end });
            const Instruction& term = BlockTransferInstruction(b);
            // The latch terminator's condition text is composed in the branch pass
            // below, which checks this set to phrase it as a loop condition.
            if (isCondJump(term)) loopTermVAs.insert(term.address);
            note(h.insns.front().address, NoteKind::Loop,
                 "loop start (back edge from " + vaHex(term.address) + ")",
                 "block at " + vaHex(h.start) + " is re-entered from " + vaHex(b.start) +
                 " (address-order back edge; natural-loop approximation)", 0.7f);
        }
    }

    // ---- 6) Branch meaning + return-value-use + calls -----------------------
    for (int bi : order) {
        const BasicBlock& b = g.blocks[bi];
        if (b.insns.empty()) continue;

        // Switch dispatch.
        if (b.isSwitch) {
            const Instruction& term = BlockTransferInstruction(b);
            note(term.address, NoteKind::Switch,
                 "switch via jump table — " + std::to_string(b.caseTargets.size()) + " case(s)",
                 "indirect jmp resolved to a jump table with " + std::to_string(b.caseTargets.size()) +
                 " in-bounds targets", 0.9f);
        }

        for (size_t k = 0; k < b.insns.size(); ++k) {
            const Instruction& in = b.insns[k];

            // ---- calls ----
            if (in.isCall) {
                size_t apiObservationIndex = static_cast<size_t>(-1);
                std::string nm = callName(in);
                bool indirect = nm.empty() && !HasBranchTarget(in);
                // Argument sniffing: scan backwards for the most recent writes to arg
                // regs (x64) / pushes (x86) since the previous call/branch.
                std::vector<std::string> argTexts;
                std::vector<ApiArgumentObservation> argObservations;
                if (x64) {
                    struct RecoveredArg {
                        std::string value;
                        std::string sourceExpression;
                        bool sourceIsAddress = false;
                        uint64_t referencedAddress = 0;
                        bool referencedAddressValid = false;
                        uint64_t immediate = 0;
                        bool immediateValid = false;
                        std::string stringLiteral;
                        bool stringLiteralTruncated = false;
                    };
                    std::map<std::string, RecoveredArg> argVal;
                    // Microsoft x64 places argument five and later in eight-byte
                    // stack slots after the 32-byte shadow space. Recover direct
                    // stores to those slots independently from the four register
                    // arguments. The value is still best-effort and remains
                    // validity-bearing; merely seeing a slot never invents a
                    // literal or pointer.
                    std::map<uint32_t, RecoveredArg> stackArgVal;
                    size_t back = 0;
                    for (size_t j = k; j-- > 0 && back < 24; ++back) {
                        const Instruction& p = b.insns[j];
                        if (p.isCall || (p.isBranch && !p.isCall)) break;
                        std::vector<std::string> ops = splitOps(p.operands);
                        if (ops.empty()) continue;
                        std::string dst = canonReg(ops[0]);
                        const bool isArgR = dst == "rcx" || dst == "rdx" ||
                                            dst == "r8" || dst == "r9";
                        const MemOp stackDestination = parseMem(ops[0]);
                        const bool isStackArgument = ops.size() == 2 &&
                            p.mnemonic.rfind("mov", 0) == 0 && stackDestination.ok &&
                            stackDestination.base == "rsp" && stackDestination.index.empty() &&
                            stackDestination.hasDisp && stackDestination.disp >= 0x20 &&
                            ((stackDestination.disp - 0x20) % 8) == 0 &&
                            stackDestination.disp <= 0xF8;
                        if (isStackArgument) {
                            const uint32_t argumentIndex = static_cast<uint32_t>(
                                4 + (stackDestination.disp - 0x20) / 8);
                            if (!stackArgVal.count(argumentIndex)) {
                                RecoveredArg recovered;
                                recovered.sourceExpression = ops[1];
                                int64_t directImmediate = 0;
                                const bool hasDirectImmediate = parseImm(ops[1], directImmediate);
                                uint64_t ref = 0;
                                bool hasRef = false;
                                if (hasDirectImmediate) {
                                    const uint64_t candidate = static_cast<uint64_t>(directImmediate);
                                    if (!stringFor(candidate).empty() || !nameFor(candidate).empty()) {
                                        ref = candidate;
                                        hasRef = true;
                                        recovered.sourceIsAddress = true;
                                    }
                                }
                                const std::string sourceRegister = canonReg(ops[1]);
                                if (!hasRef && !sourceRegister.empty()) {
                                    size_t traced = 0;
                                    for (size_t q = j; q-- > 0 && traced < 8; ++traced) {
                                        const Instruction& producer = b.insns[q];
                                        if (producer.isCall || (producer.isBranch && !producer.isCall)) break;
                                        const std::vector<std::string> producerOps = splitOps(producer.operands);
                                        if (producerOps.size() != 2 ||
                                            canonReg(producerOps[0]) != sourceRegister)
                                            continue;
                                        recovered.sourceExpression = producerOps[1];
                                        recovered.sourceIsAddress =
                                            producer.mnemonic == "lea";
                                        int64_t producerImmediate = 0;
                                        if (parseImm(producerOps[1], producerImmediate)) {
                                            const uint64_t candidate = static_cast<uint64_t>(producerImmediate);
                                            if (!stringFor(candidate).empty() || !nameFor(candidate).empty()) {
                                                ref = candidate;
                                                hasRef = true;
                                                recovered.sourceIsAddress = true;
                                            } else {
                                                recovered.immediate = candidate;
                                                recovered.immediateValid = true;
                                            }
                                        } else if (TryGetInstrDataRef(producer, ref) ||
                                                   TryGetInstrImmRef(producer, ref)) {
                                            hasRef = true;
                                        }
                                        break;
                                    }
                                }
                                if (hasRef) {
                                    recovered.referencedAddress = ref;
                                    recovered.referencedAddressValid = true;
                                    const std::string literal = stringFor(ref);
                                    if (!literal.empty()) {
                                        recovered.stringLiteralTruncated =
                                            literal.size() > 40;
                                        recovered.stringLiteral = literal.substr(0, 40);
                                        recovered.value = "\"" + recovered.stringLiteral + "\"";
                                    } else {
                                        const std::string symbol = nameFor(ref);
                                        recovered.value = symbol.empty() ? ("&" + vaHex(ref))
                                                                         : ("&" + symbol);
                                    }
                                } else if (hasDirectImmediate) {
                                    recovered.immediate = static_cast<uint64_t>(directImmediate);
                                    recovered.immediateValid = true;
                                    recovered.value = vaHex(recovered.immediate);
                                } else if (recovered.immediateValid) {
                                    recovered.value = vaHex(recovered.immediate);
                                } else {
                                    recovered.value = ops[1].substr(0, 24);
                                }
                                if (!recovered.value.empty())
                                    stackArgVal.emplace(argumentIndex, std::move(recovered));
                            }
                        }
                        if (!isArgR || argVal.count(dst)) continue;
                        RecoveredArg recovered;
                        const bool selfZero = (p.mnemonic == "xor" || p.mnemonic == "sub") &&
                                              ops.size() == 2 && canonReg(ops[1]) == dst;
                        if (selfZero) {
                            recovered.value = "0";
                            recovered.sourceExpression = "0";
                            recovered.immediate = 0;
                            recovered.immediateValid = true;
                        }
                        else if (p.mnemonic == "lea" || p.mnemonic.rfind("mov", 0) == 0) {
                            recovered.sourceIsAddress = p.mnemonic == "lea";
                            uint64_t ref = 0;
                            bool hasRef = TryGetInstrDataRef(p, ref);
                            int64_t directImmediate = 0;
                            const bool hasDirectImmediate = ops.size() == 2 &&
                                                            parseImm(ops[1], directImmediate);
                            if (!hasRef && hasDirectImmediate) {
                                // Let the caller's resolvers prove that an
                                // immediate is an address. Otherwise preserve it
                                // as the scalar size/flag value the API database
                                // can decode.
                                const uint64_t candidate = static_cast<uint64_t>(directImmediate);
                                if (!stringFor(candidate).empty() || !nameFor(candidate).empty()) {
                                    ref = candidate;
                                    hasRef = true;
                                }
                            }
                            if (!hasRef && !hasDirectImmediate) {
                                hasRef = TryGetInstrImmRef(p, ref);
                            }
                            if (hasRef) {
                                std::string s = stringFor(ref);
                                recovered.referencedAddress = ref;
                                recovered.referencedAddressValid = true;
                                recovered.sourceExpression = ops.size() == 2 ? ops[1] : std::string();
                                recovered.sourceIsAddress =
                                    p.mnemonic == "lea" || hasDirectImmediate;
                                if (!s.empty()) {
                                    recovered.stringLiteralTruncated = s.size() > 40;
                                    recovered.stringLiteral = s.substr(0, 40);
                                    recovered.value = "\"" + recovered.stringLiteral + "\"";
                                } else {
                                    std::string n2 = nameFor(ref);
                                    recovered.value = n2.empty() ? ("&" + vaHex(ref)) : ("&" + n2);
                                }
                            } else if (ops.size() == 2) {
                                if (hasDirectImmediate) {
                                    recovered.immediate = static_cast<uint64_t>(directImmediate);
                                    recovered.immediateValid = true;
                                    recovered.value = vaHex(recovered.immediate);
                                    recovered.sourceExpression = ops[1];
                                } else {
                                    recovered.value = ops[1].substr(0, 24);
                                    recovered.sourceExpression = ops[1];
                                }
                            }
                        }
                        if (!recovered.value.empty()) argVal[dst] = std::move(recovered);
                        // Continue looking farther back for other argument
                        // registers; only a write to the register currently
                        // being recovered prevents an earlier value from
                        // reaching the call.
                    }
                    uint32_t argIndex = 0;
                    for (const char* a : kArgRegs64) {
                        auto it = argVal.find(a);
                        if (it != argVal.end()) {
                            argTexts.push_back(std::string(a) + "=" + it->second.value);
                            ApiArgumentObservation observed;
                            observed.index = argIndex;
                            observed.abiLocation = a;
                            observed.renderedValue = it->second.value;
                            observed.referencedAddress = it->second.referencedAddress;
                            observed.referencedAddressValid = it->second.referencedAddressValid;
                            observed.immediate = it->second.immediate;
                            observed.immediateValid = it->second.immediateValid;
                            observed.stringLiteral = it->second.stringLiteral;
                            observed.stringLiteralTruncated =
                                it->second.stringLiteralTruncated;
                            observed.sourceExpression = it->second.sourceExpression;
                            observed.sourceIsAddress = it->second.sourceIsAddress;
                            observed.confidence = 0.6f;
                            observed.evidence = "value traced backward within the current basic block";
                            argObservations.push_back(std::move(observed));
                        }
                        ++argIndex;
                    }
                    for (const auto& [index, recovered] : stackArgVal) {
                        const std::string location = "arg" + std::to_string(index + 1);
                        argTexts.push_back(location + "=" + recovered.value);
                        ApiArgumentObservation observed;
                        observed.index = index;
                        char slot[32];
                        std::snprintf(slot, sizeof(slot), "[rsp+0x%X]",
                                      0x20u + (index - 4u) * 8u);
                        observed.abiLocation = slot;
                        observed.renderedValue = recovered.value;
                        observed.referencedAddress = recovered.referencedAddress;
                        observed.referencedAddressValid = recovered.referencedAddressValid;
                        observed.immediate = recovered.immediate;
                        observed.immediateValid = recovered.immediateValid;
                        observed.stringLiteral = recovered.stringLiteral;
                        observed.stringLiteralTruncated =
                            recovered.stringLiteralTruncated;
                        observed.sourceExpression = recovered.sourceExpression;
                        observed.sourceIsAddress = recovered.sourceIsAddress;
                        observed.confidence = 0.55f;
                        observed.evidence =
                            "Microsoft x64 stack argument traced backward within the current basic block";
                        argObservations.push_back(std::move(observed));
                    }
                } else {
                    // x86: pushes between the previous call/branch and this call, last push = arg1.
                    struct RecoveredPush {
                        std::string value;
                        std::string sourceExpression;
                        bool sourceIsAddress = false;
                        uint64_t referencedAddress = 0;
                        bool referencedAddressValid = false;
                        uint64_t immediate = 0;
                        bool immediateValid = false;
                        std::string stringLiteral;
                        bool stringLiteralTruncated = false;
                    };
                    std::vector<RecoveredPush> pushes;
                    for (size_t j = k; j-- > 0 && pushes.size() < 6;) {
                        const Instruction& p = b.insns[j];
                        if (p.isCall || (p.isBranch && !p.isCall)) break;
                        if (p.mnemonic == "push") {
                            RecoveredPush recovered;
                            int64_t directImmediate = 0;
                            const bool hasDirectImmediate =
                                parseImm(p.operands, directImmediate);
                            uint64_t ref = 0;
                            if (TryGetInstrImmRef(p, ref)) {
                                std::string s = stringFor(ref);
                                std::string n = nameFor(ref);
                                recovered.referencedAddress = ref;
                                recovered.referencedAddressValid = !s.empty() || !n.empty() || ref >= 0x1000;
                                recovered.sourceExpression = p.operands;
                                recovered.sourceIsAddress =
                                    recovered.referencedAddressValid;
                                if (!s.empty()) {
                                    recovered.stringLiteralTruncated = s.size() > 40;
                                    recovered.stringLiteral = s.substr(0, 40);
                                    recovered.value = "\"" + recovered.stringLiteral + "\"";
                                } else if (!n.empty()) recovered.value = "&" + n;
                                else if (ref >= 0x1000) recovered.value = "&" + vaHex(ref);
                                else recovered.value = p.operands.substr(0, 24);
                                if (!recovered.referencedAddressValid && hasDirectImmediate) {
                                    recovered.immediate =
                                        static_cast<uint64_t>(directImmediate);
                                    recovered.immediateValid = true;
                                }
                            } else {
                                recovered.value = p.operands.substr(0, 24);
                                recovered.sourceExpression = p.operands;
                                if (hasDirectImmediate) {
                                    recovered.immediate =
                                        static_cast<uint64_t>(directImmediate);
                                    recovered.immediateValid = true;
                                }
                                const std::string pushedReg = canonReg(p.operands);
                                if (!pushedReg.empty()) {
                                    size_t traced = 0;
                                    for (size_t q = j; q-- > 0 && traced < 8; ++traced) {
                                        const Instruction& producer = b.insns[q];
                                        if (producer.isCall || (producer.isBranch && !producer.isCall)) break;
                                        const std::vector<std::string> producerOps = splitOps(producer.operands);
                                        if (producerOps.empty() || canonReg(producerOps[0]) != pushedReg)
                                            continue;
                                        if (producerOps.size() == 2 &&
                                            (producer.mnemonic == "lea" ||
                                             producer.mnemonic.rfind("mov", 0) == 0)) {
                                            recovered.sourceExpression = producerOps[1];
                                            recovered.sourceIsAddress =
                                                producer.mnemonic == "lea";
                                            uint64_t producerRef = 0;
                                            if (TryGetInstrDataRef(producer, producerRef) ||
                                                TryGetInstrImmRef(producer, producerRef)) {
                                                recovered.referencedAddress = producerRef;
                                                recovered.referencedAddressValid = true;
                                                const std::string resolved = stringFor(producerRef);
                                                if (!resolved.empty()) {
                                                    recovered.stringLiteralTruncated =
                                                        resolved.size() > 40;
                                                    recovered.stringLiteral =
                                                        resolved.substr(0, 40);
                                                }
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                            pushes.push_back(std::move(recovered));
                        }
                    }
                    for (size_t j = 0; j < pushes.size(); ++j) {
                        const std::string location = "arg" + std::to_string(j + 1);
                        argTexts.push_back(location + "=" + pushes[j].value);
                        ApiArgumentObservation observed;
                        observed.index = static_cast<uint32_t>(j);
                        observed.abiLocation = location;
                        observed.renderedValue = pushes[j].value;
                        observed.referencedAddress = pushes[j].referencedAddress;
                        observed.referencedAddressValid = pushes[j].referencedAddressValid;
                        observed.immediate = pushes[j].immediate;
                        observed.immediateValid = pushes[j].immediateValid;
                        observed.stringLiteral = pushes[j].stringLiteral;
                        observed.stringLiteralTruncated =
                            pushes[j].stringLiteralTruncated;
                        observed.sourceExpression = pushes[j].sourceExpression;
                        observed.sourceIsAddress = pushes[j].sourceIsAddress;
                        observed.confidence = 0.55f;
                        observed.evidence = "push traced backward within the current basic block";
                        argObservations.push_back(std::move(observed));
                    }
                }

                if (indirect) {
                    // Virtual-call pattern: dispatch reg loaded from [obj] shortly before.
                    MemOp cm = parseMem(in.operands);
                    std::string dispReg = !cm.ok ? canonReg(in.operands) : cm.base;
                    bool isVirtual = false; std::string objReg; int64_t slot = cm.ok ? cm.disp : 0;
                    if (!dispReg.empty()) {
                        for (size_t j = k; j-- > 0 && k - j <= 6;) {
                            const Instruction& p = b.insns[j];
                            std::vector<std::string> ops = splitOps(p.operands);
                            if (ops.size() == 2 && p.mnemonic == "mov" && canonReg(ops[0]) == dispReg) {
                                MemOp lm = parseMem(ops[1]);
                                if (lm.ok && !lm.base.empty() && (!lm.hasDisp || lm.disp == 0) &&
                                    lm.base != "rbp" && lm.base != "rsp") {
                                    isVirtual = true; objReg = lm.base;
                                }
                                break;
                            }
                            if (p.isCall) break;
                        }
                    }
                    if (isVirtual) {
                        std::string txt = "likely virtual call: vtable from [" + regDisplay(objReg, x64) +
                                          "], slot +" + vaHex((uint64_t)slot);
                        if (objReg == "rcx") txt += " (this in " + regDisplay("rcx", x64) + ")";
                        note(in.address, NoteKind::VirtualCall, txt,
                             "mov " + dispReg + ", [" + objReg + "] followed by call through " + dispReg +
                             " — classic vtable dispatch shape (heuristic)", 0.55f);
                    } else {
                        note(in.address, NoteKind::IndirectCall,
                             "indirect call through " + in.operands + " — target decided at runtime",
                             "no static target; register/computed-memory call", 0.8f);
                    }
                } else if (!nm.empty()) {
                    applyApiArgumentKnowledge(nm, x64, argTexts);
                    const ApiPrototypeInfo* prototype = FindWindowsApiPrototype(nm);
                    for (size_t j = 0; j < argObservations.size(); ++j) {
                        if (j < argTexts.size()) {
                            const size_t equals = argTexts[j].find('=');
                            if (equals != std::string::npos)
                                argObservations[j].renderedValue = argTexts[j].substr(equals + 1);
                        }
                        const uint32_t argumentIndex = argObservations[j].index;
                        if (prototype && argumentIndex < prototype->parameterCount)
                            argObservations[j].parameter = prototype->parameters[argumentIndex].name;
                    }
                    ApiCallObservation observed;
                    observed.callVA = in.address;
                    observed.callVAValid = true;
                    observed.targetVA = in.branchTarget;
                    observed.targetVAValid = HasBranchTarget(in);
                    observed.resolvedName = nm;
                    observed.arguments = argObservations;
                    observed.confidence = argObservations.empty() ? 0.75f : 0.6f;
                    observed.evidence = "named call target resolved by the caller";
                    if (!argObservations.empty())
                        observed.evidence += "; arguments traced within the current basic block";
                    out.apiCalls.push_back(std::move(observed));
                    apiObservationIndex = out.apiCalls.size() - 1;
                    std::string purpose = ApiPurpose(nm);
                    std::string txt;
                    if (!purpose.empty()) txt = purpose;
                    if (!argTexts.empty()) {
                        if (!txt.empty()) txt += " — ";
                        txt += "args: ";
                        for (size_t j = 0; j < argTexts.size(); ++j) { if (j) txt += ", "; txt += argTexts[j]; }
                    }
                    if (!txt.empty()) {
                        std::string evidence = "call to " + nm;
                        if (!argTexts.empty()) {
                            evidence += "; argument registers/pushes traced back within this block (best-effort)";
                            if (FindWindowsApiPrototype(nm))
                                evidence += "; parameter names/constants from bounded Windows API database";
                        }
                        note(in.address, NoteKind::Call, txt, evidence,
                             argTexts.empty() ? 0.75f : 0.6f);
                    }
                }

                // Return-value use: scan forward for a read of rax before a write.
                {
                    int seen = 0; bool decided = false;
                    auto scanInsn = [&](const Instruction& q) -> bool {   // true = stop
                        RW rw = classifyRW(q);
                        bool reads = false, writes = false;
                        for (auto& r : rw.reads) if (r == "rax") reads = true;
                        for (auto& r : rw.writes) if (r == "rax") writes = true;
                        auto instructionText = [](const Instruction& value) {
                            return value.operands.empty()
                                 ? value.mnemonic
                                 : value.mnemonic + " " + value.operands;
                        };
                        auto recordUse = [&](ApiReturnUseKind kind,
                                             const std::string& summary,
                                             const std::string& evidence,
                                             float confidence,
                                             const Instruction* branch = nullptr) {
                            if (apiObservationIndex >= out.apiCalls.size()) return;
                            ApiCallObservation& observed = out.apiCalls[apiObservationIndex];
                            observed.returnValueUsed = kind != ApiReturnUseKind::Ignored;
                            observed.returnValueUseKnown = true;
                            observed.returnUseVA = q.address;
                            observed.returnUseVAValid = true;
                            observed.returnUseKind = kind;
                            observed.returnUseInstruction = instructionText(q);
                            observed.returnUseSummary = summary;
                            observed.resultInfluencesDecision = branch != nullptr;
                            if (branch) {
                                observed.decisionVA = branch->address;
                                observed.decisionVAValid = true;
                                observed.decisionTarget = branch->branchTarget;
                                observed.decisionTargetValid = HasBranchTarget(*branch);
                                observed.decisionInstruction = instructionText(*branch);
                            }
                            observed.returnUseEvidence = evidence;
                            observed.returnUseConfidence = confidence;
                        };
                        // A call immediately returned without an intervening
                        // overwrite propagates the callee result to this
                        // function's caller. `ret` has no explicit rax operand,
                        // so model that ABI use before the textual RW check.
                        if (InstructionIsReturn(q)) {
                            const std::string evidence =
                                "the function returns before the ABI return register is overwritten";
                            const std::string summary =
                                "returned unchanged by the enclosing function at " + vaHex(q.address);
                            note(in.address, NoteKind::RetUse, "return value is " + summary,
                                 evidence, 0.7f);
                            recordUse(ApiReturnUseKind::Returned, summary, evidence, 0.7f);
                            decided = true; return true;
                        }
                        if (reads && !rw.zeroIdiom) {
                            const Instruction* decisionBranch = nullptr;
                            if (q.mnemonic == "cmp" || q.mnemonic == "test") {
                                for (const BasicBlock& candidate : g.blocks) {
                                    for (size_t qi = 0; qi < candidate.insns.size(); ++qi) {
                                        if (candidate.insns[qi].address != q.address) continue;
                                        const size_t stop = (std::min)(candidate.insns.size(), qi + 5);
                                        for (size_t ni = qi + 1; ni < stop; ++ni) {
                                            const Instruction& next = candidate.insns[ni];
                                            if (isCondJump(next)) {
                                                decisionBranch = &next;
                                                break;
                                            }
                                            // A call or another flag-producing
                                            // instruction severs the cmp/test ->
                                            // Jcc relationship.  Looking past it
                                            // would falsely attribute an unrelated
                                            // branch to this API result.
                                            if (InstructionIsCall(next) || isFlagSetter(next) ||
                                                InstructionEndsBlock(next))
                                                break;
                                        }
                                        break;
                                    }
                                    if (decisionBranch) break;
                                }
                            }
                            ApiReturnUseKind useKind = ApiReturnUseKind::Consumed;
                            std::string how = "consumed at " + vaHex(q.address);
                            const std::vector<std::string> operands = splitOps(q.operands);
                            if (decisionBranch) {
                                useKind = ApiReturnUseKind::Branched;
                                how = "checked at " + vaHex(q.address) +
                                      "; controls " + instructionText(*decisionBranch) +
                                      " at " + vaHex(decisionBranch->address);
                            } else if (q.mnemonic == "cmp" || q.mnemonic == "test") {
                                useKind = ApiReturnUseKind::Compared;
                                how = "checked at " + vaHex(q.address);
                            } else if (writesMemFirstOp(q)) {
                                useKind = ApiReturnUseKind::Stored;
                                const std::string destination =
                                    !operands.empty() && operands[0].find('[') != std::string::npos
                                    ? operands[0] : "memory";
                                how = "stored in " + destination + " at " + vaHex(q.address);
                            } else if (q.mnemonic == "push" ||
                                       (q.mnemonic.rfind("mov", 0) == 0 &&
                                        !operands.empty() && canonReg(operands[0]) != "rax")) {
                                useKind = ApiReturnUseKind::Propagated;
                                how = "copied/passed onward by `" + instructionText(q) +
                                      "` at " + vaHex(q.address);
                            }
                            std::string evidence = instructionText(q) + " reads " +
                                regDisplay("rax", x64) + " before anything overwrites it";
                            if (decisionBranch)
                                evidence += "; the nearby conditional branch consumes the flags";
                            const float confidence = decisionBranch ? 0.75f : 0.7f;
                            note(in.address, NoteKind::RetUse, "return value is " + how,
                                 evidence, confidence);
                            recordUse(useKind, how, evidence, confidence, decisionBranch);
                            decided = true; return true;
                        }
                        if (writes) {
                            const std::string evidence = instructionText(q) + " overwrites " +
                                regDisplay("rax", x64) +
                                " before any read (window-limited check)";
                            const std::string summary = "ignored; overwritten at " + vaHex(q.address);
                            note(in.address, NoteKind::RetUse, "return value not used (overwritten at " +
                                 vaHex(q.address) + ")",
                                 evidence, 0.5f);
                            recordUse(ApiReturnUseKind::Ignored, summary, evidence, 0.5f);
                            decided = true; return true;
                        }
                        return false;
                    };
                    for (size_t j = k + 1; j < b.insns.size() && seen < 8 && !decided; ++j, ++seen)
                        if (scanInsn(b.insns[j])) break;
                    if (!decided && seen < 8 && b.succ.size() == 1) {
                        // Follow only a unique fallthrough successor. Choosing
                        // one arm of a split could falsely label the result
                        // ignored while another reachable arm still uses it.
                        for (size_t s : b.succ) {
                            if (s >= g.blocks.size()) continue;
                            const BasicBlock& nb = g.blocks[s];
                            if (nb.start != b.end) continue;   // only the fallthrough
                            for (size_t j = 0; j < nb.insns.size() && seen < 8 && !decided; ++j, ++seen)
                                if (scanInsn(nb.insns[j])) break;
                            break;
                        }
                    }
                }
            }

            // ---- conditional branch meaning ----
            if (isCondJump(in) && k == b.insns.size() - 1) {
                // Find the flag setter scanning backwards in this block.
                const Instruction* fs = nullptr;
                for (size_t j = k; j-- > 0;) {
                    if (isFlagSetter(b.insns[j])) { fs = &b.insns[j]; break; }
                    if (InstructionIsCall(b.insns[j])) break;   // a call clobbers flags
                }
                bool sgn = false, uns = false;
                const char* op = jccExprOp(in.mnemonic, sgn, uns);
                std::string cond, ev;
                if (fs && op) {
                    std::vector<std::string> fo = splitOps(fs->operands);
                    std::string A = fo.size() > 0 ? fo[0] : "";
                    std::string Bp = fo.size() > 1 ? fo[1] : "";
                    if (fs->mnemonic == "test" && fo.size() == 2 && A == Bp) {
                        if (!std::strcmp(op, "==")) cond = A + " == 0";
                        else if (!std::strcmp(op, "!=")) cond = A + " != 0";
                        else if (!std::strcmp(op, "s"))  cond = A + " < 0";
                        else if (!std::strcmp(op, "ns")) cond = A + " >= 0";
                        else cond = A + " " + op + " 0";
                    } else if (fs->mnemonic == "test") {
                        cond = "(" + A + " & " + Bp + ") " + (std::strcmp(op, "==") ? "!= 0" : "== 0");
                    } else if (fs->mnemonic == "cmp") {
                        if (!std::strcmp(op, "s"))      cond = A + " - " + Bp + " < 0";
                        else if (!std::strcmp(op, "ns")) cond = A + " - " + Bp + " >= 0";
                        else cond = A + " " + op + " " + Bp + (sgn ? " (signed)" : uns ? " (unsigned)" : "");
                    } else {   // arithmetic set the flags
                        cond = "result of `" + fs->mnemonic + " " + fs->operands + "` " +
                               (std::strcmp(op, "==") == 0 ? "is zero" :
                                std::strcmp(op, "!=") == 0 ? "is non-zero" :
                                std::string("compares ") + op + " 0");
                    }
                    ev = "flags set by `" + fs->mnemonic + " " + fs->operands + "` at " + vaHex(fs->address);

                    // Did the compared value come from the previous call's return?
                    std::vector<std::string> fsRegs; regsInText(fs->operands, fsRegs);
                    bool usesRax = std::find(fsRegs.begin(), fsRegs.end(), "rax") != fsRegs.end();
                    std::string callerNote, calleeNm;
                    if (usesRax) {
                        for (size_t j = k; j-- > 0;) {
                            const Instruction& p = b.insns[j];
                            if (p.address >= fs->address) continue;
                            RW rw = classifyRW(p);
                            bool wrAx = false;
                            for (auto& r : rw.writes) if (r == "rax") wrAx = true;
                            if (p.isCall) { calleeNm = callName(p); if (calleeNm.empty()) calleeNm = "the previous call"; break; }
                            if (wrAx) break;
                        }
                    }
                    std::string txt;
                    if (!calleeNm.empty() && nameLooksLikeCompare(calleeNm)) {
                        bool jumpOnNonZero = !std::strcmp(op, "!=");
                        bool jumpOnZero    = !std::strcmp(op, "==");
                        if (jumpOnNonZero)
                            txt = "jumps to " + vaHex(in.branchTarget) + " if " + calleeNm +
                                  " result is non-zero (strings/memory differ)";
                        else if (jumpOnZero)
                            txt = "jumps to " + vaHex(in.branchTarget) + " if " + calleeNm +
                                  " result is zero (contents equal)";
                        if (!txt.empty()) ev += "; " + calleeNm + " returns 0 on equality";
                    }
                    if (txt.empty()) {
                        txt = "jumps to " + vaHex(in.branchTarget) + " if " + cond;
                        if (!calleeNm.empty()) {
                            txt += " — return value of " + calleeNm + " controls this branch";
                            ev += "; value comes from " + calleeNm;
                        }
                    }
                    if (loopTermVAs.count(in.address)) {
                        txt = "loop: continues while " + cond +
                              (in.branchTarget <= in.address ? "" : " (exit branch)");
                        note(in.address, NoteKind::Loop, txt, ev + "; backward branch closes a loop", 0.7f);
                    } else {
                        note(in.address, NoteKind::Branch, txt, ev, 0.75f);
                    }
                } else if (loopTermVAs.count(in.address)) {
                    note(in.address, NoteKind::Loop,
                         "loop back edge to " + vaHex(in.branchTarget),
                         "backward conditional branch (flag source not identified)", 0.6f);
                }
            }

            // ---- vtable pointer store: lea reg, [code]; ... mov [obj], reg ----
            if (opt.looksLikeVtable && in.mnemonic == "mov") {
                std::vector<std::string> ops = splitOps(in.operands);
                if (ops.size() == 2 && ops[0].find('[') != std::string::npos) {
                    uint64_t cand = 0;
                    bool candValid = false;
                    std::string src = canonReg(ops[1]);
                    if (!src.empty()) {
                        for (size_t j = k; j-- > 0 && k - j <= 6;) {
                            const Instruction& p = b.insns[j];
                            std::vector<std::string> po = splitOps(p.operands);
                            if (po.size() == 2 && canonReg(po[0]) == src) {
                                if (p.mnemonic == "lea" || p.mnemonic == "mov") {
                                    uint64_t r = 0;
                                    candValid = TryGetInstrDataRef(p, r);
                                    if (!candValid) candValid = TryGetInstrImmRef(p, r);
                                    if (candValid) cand = r;
                                }
                                break;
                            }
                        }
                    } else {
                        int64_t imm = 0;
                        if (parseImm(ops[1], imm) && imm >= 0) {
                            cand = static_cast<uint64_t>(imm);
                            candValid = true;
                        }
                    }
                    MemOp dm = parseMem(ops[0]);
                    if (candValid && dm.ok && !dm.base.empty() && dm.base != "rbp" && dm.base != "rsp" &&
                        (!dm.hasDisp || dm.disp == 0) && opt.looksLikeVtable(cand)) {
                        note(in.address, NoteKind::Vtable,
                             "stores vtable pointer " + vaHex(cand) + " into [" + regDisplay(dm.base, x64) +
                             "] — object construction?",
                             vaHex(cand) + " holds consecutive code pointers (vtable shape) and is written to "
                             "offset 0 of an object pointer", 0.6f);
                    }
                }
            }
        }
    }

    // ---- 6b) Reply-buffer comparison -> decision flow ----------------------
    // Keep this distinct from the return-register scan above.  A networking
    // Read API's immediate return describes transport status or byte count;
    // crackme acceptance normally follows bytes written through a payload or
    // header output argument.
    {
        struct TracePoint {
            size_t block = 0;
            size_t instruction = 0;
            size_t distance = 0;
        };
        std::unordered_map<uint64_t, std::pair<size_t, size_t>> instructionLocations;
        for (size_t blockIndex = 0; blockIndex < g.blocks.size(); ++blockIndex)
            for (size_t instructionIndex = 0;
                 instructionIndex < g.blocks[blockIndex].insns.size();
                 ++instructionIndex)
                instructionLocations[g.blocks[blockIndex].insns[instructionIndex].address] =
                    { blockIndex, instructionIndex };

        auto collectReachable = [&](uint64_t afterVA, bool& complete) {
            constexpr size_t kMaxTraceInstructions = 128;
            constexpr size_t kMaxTraceBlocks = 32;
            constexpr size_t kMaxGraphDepth = 4;
            std::vector<TracePoint> points;
            complete = true;
            const auto location = instructionLocations.find(afterVA);
            if (location == instructionLocations.end()) {
                complete = false;
                return points;
            }
            const size_t sourceBlock = location->second.first;
            const size_t sourceInstruction = location->second.second;
            const BasicBlock& source = g.blocks[sourceBlock];
            size_t distance = 0;
            for (size_t i = sourceInstruction + 1; i < source.insns.size(); ++i) {
                if (points.size() >= kMaxTraceInstructions) {
                    complete = false;
                    return points;
                }
                points.push_back({ sourceBlock, i, distance++ });
            }

            struct PendingBlock { size_t block = 0, depth = 0; };
            std::deque<PendingBlock> pending;
            std::vector<size_t> successors = source.succ;
            std::sort(successors.begin(), successors.end(), [&](size_t a, size_t b) {
                return a < g.blocks.size() && b < g.blocks.size()
                     ? g.blocks[a].start < g.blocks[b].start : a < b;
            });
            for (size_t successor : successors)
                if (successor < g.blocks.size()) pending.push_back({ successor, 1 });
            std::unordered_set<size_t> visited;
            visited.insert(sourceBlock);
            size_t blocksExamined = 0;
            while (!pending.empty()) {
                const PendingBlock current = pending.front();
                pending.pop_front();
                if (current.depth > kMaxGraphDepth) {
                    complete = false;
                    continue;
                }
                if (!visited.insert(current.block).second)
                    continue;
                if (++blocksExamined > kMaxTraceBlocks) {
                    complete = false;
                    break;
                }
                const BasicBlock& block = g.blocks[current.block];
                for (size_t i = 0; i < block.insns.size(); ++i) {
                    if (points.size() >= kMaxTraceInstructions) {
                        complete = false;
                        return points;
                    }
                    points.push_back({ current.block, i, distance++ });
                }
                std::vector<size_t> next = block.succ;
                std::sort(next.begin(), next.end(), [&](size_t a, size_t b) {
                    return a < g.blocks.size() && b < g.blocks.size()
                         ? g.blocks[a].start < g.blocks[b].start : a < b;
                });
                for (size_t successor : next)
                    if (successor < g.blocks.size() && !visited.count(successor))
                        pending.push_back({ successor, current.depth + 1 });
            }
            return points;
        };

        auto nearbyDecisionBranch = [&](size_t blockIndex, size_t comparisonIndex)
                -> const Instruction* {
            if (blockIndex >= g.blocks.size()) return nullptr;
            const BasicBlock& block = g.blocks[blockIndex];
            const size_t stop = (std::min)(block.insns.size(), comparisonIndex + 5);
            for (size_t i = comparisonIndex + 1; i < stop; ++i) {
                const Instruction& candidate = block.insns[i];
                if (isCondJump(candidate)) return &candidate;
                if (InstructionIsCall(candidate) || isFlagSetter(candidate) ||
                    InstructionEndsBlock(candidate))
                    break;
            }
            return nullptr;
        };

        auto fillDecisionPaths = [&](auto& decision,
                                     const Instruction* branch,
                                     bool equalityComparison,
                                     bool zeroConditionMeansMatch,
                                     const std::string& matchText,
                                     const std::string& mismatchText) {
            if (!branch) return;
            decision.decisionVA = branch->address;
            decision.decisionVAValid = true;
            decision.decisionTarget = branch->branchTarget;
            decision.decisionTargetValid = HasBranchTarget(*branch);
            decision.fallthroughVAValid = branch->length != 0 &&
                branch->address <= (std::numeric_limits<uint64_t>::max)() -
                                   branch->length;
            decision.fallthroughVA = decision.fallthroughVAValid
                                   ? branch->address + branch->length : 0;
            decision.decisionInstruction = instructionText(*branch);
            const std::string mnemonic = toLower(branch->mnemonic);
            const bool jumpsOnEqual = mnemonic == "je" || mnemonic == "jz";
            const bool jumpsOnDifferent = mnemonic == "jne" || mnemonic == "jnz";
            if (equalityComparison && (jumpsOnEqual || jumpsOnDifferent)) {
                const bool targetIsMatch = zeroConditionMeansMatch
                                         ? jumpsOnEqual : jumpsOnDifferent;
                decision.takenPathSummary = targetIsMatch ? matchText : mismatchText;
                decision.fallthroughPathSummary = targetIsMatch ? mismatchText : matchText;
                if (targetIsMatch) {
                    decision.matchVA = decision.decisionTarget;
                    decision.matchVAValid = decision.decisionTargetValid;
                    decision.mismatchVA = decision.fallthroughVA;
                    decision.mismatchVAValid = decision.fallthroughVAValid;
                } else {
                    decision.mismatchVA = decision.decisionTarget;
                    decision.mismatchVAValid = decision.decisionTargetValid;
                    decision.matchVA = decision.fallthroughVA;
                    decision.matchVAValid = decision.fallthroughVAValid;
                }
            } else {
                decision.takenPathSummary = "comparison condition is true";
                decision.fallthroughPathSummary = "comparison condition is false";
            }
        };

        auto instructionReferencesOrigin = [&](const Instruction& instruction,
                                                 const std::string& operand,
                                                 const OutputBufferOrigin& origin,
                                                size_t blockIndex,
                                                size_t instructionIndex) {
            const MemOp memory = parseMem(operand);
            if (memoryAliasesOutputOrigin(memory, origin)) return true;
            if (origin.referencedAddressValid) {
                uint64_t reference = 0;
                if (TryGetInstrDataRef(instruction, reference) &&
                    reference >= origin.referencedAddress &&
                    reference - origin.referencedAddress <= 512)
                    return true;
            }

            const std::string scalarRegister = canonReg(operand);
            if (scalarRegister.empty() || blockIndex >= g.blocks.size()) return false;
            const BasicBlock& block = g.blocks[blockIndex];
            size_t inspected = 0;
            for (size_t i = instructionIndex; i-- > 0 && inspected < 8; ++inspected) {
                const Instruction& producer = block.insns[i];
                const RW rw = classifyRW(producer);
                if (std::find(rw.writes.begin(), rw.writes.end(), scalarRegister) ==
                    rw.writes.end())
                    continue;
                const std::vector<std::string> operands = splitOps(producer.operands);
                if (operands.size() == 2 &&
                    (producer.mnemonic == "mov" || producer.mnemonic == "movzx" ||
                     producer.mnemonic == "movsx" || producer.mnemonic == "movsxd") &&
                     memoryAliasesOutputOrigin(parseMem(operands[1]), origin))
                    return true;
                return false;
            }
            return false;
        };

        auto instructionExactlyReferencesOrigin = [&](const Instruction& instruction,
                                                        const std::string& operand,
                                                        const OutputBufferOrigin& origin,
                                                        size_t blockIndex,
                                                        size_t instructionIndex,
                                                        uint64_t producerCallVA) {
            if (memoryExactlyAliasesOutputOrigin(parseMem(operand), origin)) return true;
            if (origin.referencedAddressValid) {
                uint64_t reference = 0;
                if (TryGetInstrDataRef(instruction, reference) &&
                    reference == origin.referencedAddress)
                    return true;
            }

            const std::string scalarRegister = canonReg(operand);
            if (scalarRegister.empty() || blockIndex >= g.blocks.size()) return false;
            const BasicBlock& block = g.blocks[blockIndex];
            size_t inspected = 0;
            for (size_t i = instructionIndex; i-- > 0 && inspected < 8; ++inspected) {
                const Instruction& valueProducer = block.insns[i];
                // The register value must be loaded after this exact input
                // producer. A nonvolatile register can survive the call while
                // still holding stale pre-input bytes from the same buffer.
                if (valueProducer.address == producerCallVA) return false;
                const RW rw = classifyRW(valueProducer);
                if (std::find(rw.writes.begin(), rw.writes.end(), scalarRegister) ==
                    rw.writes.end())
                    continue;
                const std::vector<std::string> operands = splitOps(valueProducer.operands);
                if (operands.size() == 2 &&
                    (valueProducer.mnemonic == "mov" || valueProducer.mnemonic == "movzx" ||
                     valueProducer.mnemonic == "movsx" || valueProducer.mnemonic == "movsxd")) {
                    if (memoryExactlyAliasesOutputOrigin(parseMem(operands[1]), origin))
                        return true;
                    uint64_t reference = 0;
                    if (origin.referencedAddressValid &&
                        TryGetInstrDataRef(valueProducer, reference) &&
                        reference == origin.referencedAddress)
                        return true;
                }
                return false;
            }
            return false;
        };

        auto equalityResultBranch = [&](const ApiCallObservation& comparisonCall,
                                        int64_t equalityResult,
                                        bool& traceComplete,
                                        const Instruction*& comparison,
                                        const Instruction*& branch) {
            comparison = nullptr;
            branch = nullptr;
            constexpr size_t kMaxResultInstructions = 24;
            constexpr size_t kMaxResultStates = 32;
            constexpr size_t kMaxResultDepth = 4;
            const auto callLocation = instructionLocations.find(comparisonCall.callVA);
            if (callLocation == instructionLocations.end()) {
                traceComplete = false;
                return;
            }

            struct ResultPathState {
                size_t block = 0;
                size_t nextInstruction = 0;
                size_t depth = 0;
                std::unordered_set<std::string> aliases;
                std::vector<size_t> pathBlocks;
            };
            std::deque<ResultPathState> pending;
            ResultPathState initial;
            initial.block = callLocation->second.first;
            initial.nextInstruction = callLocation->second.second + 1;
            initial.aliases.insert("rax");
            initial.pathBlocks.push_back(initial.block);
            pending.push_back(std::move(initial));

            size_t statesExamined = 0;
            size_t instructionsExamined = 0;
            while (!pending.empty()) {
                ResultPathState state = std::move(pending.front());
                pending.pop_front();
                if (++statesExamined > kMaxResultStates ||
                    state.block >= g.blocks.size()) {
                    traceComplete = false;
                    return;
                }
                const BasicBlock& block = g.blocks[state.block];
                bool pathAlive = true;
                for (size_t instructionIndex = state.nextInstruction;
                     instructionIndex < block.insns.size(); ++instructionIndex) {
                    if (++instructionsExamined > kMaxResultInstructions) {
                        traceComplete = false;
                        return;
                    }
                    const Instruction& instruction = block.insns[instructionIndex];
                    const std::vector<std::string> operands =
                        splitOps(instruction.operands);
                    bool equalityTest = false;
                    if (instruction.mnemonic == "test" && equalityResult == 0 &&
                        operands.size() == 2) {
                        const std::string left = canonReg(operands[0]);
                        const std::string right = canonReg(operands[1]);
                        equalityTest = !left.empty() && left == right &&
                                       state.aliases.count(left);
                    } else if (instruction.mnemonic == "cmp" &&
                               operands.size() == 2) {
                        int64_t immediate = 0;
                        const std::string left = canonReg(operands[0]);
                        const std::string right = canonReg(operands[1]);
                        if (!left.empty() && state.aliases.count(left) &&
                            parseImm(operands[1], immediate) &&
                            immediate == equalityResult)
                            equalityTest = true;
                        else if (!right.empty() && state.aliases.count(right) &&
                                 parseImm(operands[0], immediate) &&
                                 immediate == equalityResult)
                            equalityTest = true;
                    }
                    if (equalityTest) {
                        const Instruction* candidateBranch =
                            nearbyDecisionBranch(state.block, instructionIndex);
                        if (candidateBranch) {
                            comparison = &instruction;
                            branch = candidateBranch;
                            return;
                        }
                    }

                    std::string copiedDestination;
                    if (instruction.mnemonic == "mov" && operands.size() == 2) {
                        const std::string source = canonReg(operands[1]);
                        const std::string destination = canonReg(operands[0]);
                        if (!destination.empty() && !source.empty() &&
                            state.aliases.count(source))
                            copiedDestination = destination;
                    }
                    const RW rw = classifyRW(instruction);
                    for (const std::string& written : rw.writes)
                        state.aliases.erase(written);
                    if (!copiedDestination.empty())
                        state.aliases.insert(copiedDestination);
                    if (state.aliases.empty()) {
                        pathAlive = false;
                        break;
                    }
                }
                if (!pathAlive) continue;

                std::vector<size_t> successors = block.succ;
                std::sort(successors.begin(), successors.end(),
                    [&](size_t left, size_t right) {
                        return left < g.blocks.size() && right < g.blocks.size()
                            ? g.blocks[left].start < g.blocks[right].start
                            : left < right;
                    });
                for (size_t successor : successors) {
                    if (successor >= g.blocks.size()) {
                        traceComplete = false;
                        continue;
                    }
                    if (state.depth + 1 > kMaxResultDepth) {
                        traceComplete = false;
                        continue;
                    }
                    if (std::find(state.pathBlocks.begin(), state.pathBlocks.end(),
                                  successor) != state.pathBlocks.end()) {
                        traceComplete = false;
                        continue;
                    }
                    ResultPathState next;
                    next.block = successor;
                    next.depth = state.depth + 1;
                    next.aliases = state.aliases;
                    next.pathBlocks = state.pathBlocks;
                    next.pathBlocks.push_back(successor);
                    pending.push_back(std::move(next));
                }
            }
        };

        for (size_t producerIndex = 0; producerIndex < out.apiCalls.size(); ++producerIndex) {
            ApiCallObservation& producer = out.apiCalls[producerIndex];
            const auto network = exactNetworkApiForName(producer.resolvedName);
            if (!network || network->stage != NetworkStage::Read) continue;
            const auto contract = LookupNetworkApiReturnContract(
                network->dll, network->canonicalName);
            if (!contract) continue;

            std::vector<NetworkApiOutParameter> contentOutputs;
            for (uint8_t outputIndex = 0;
                 outputIndex < contract->outParameterCount; ++outputIndex) {
                const NetworkApiOutParameter& output = contract->outParameters[outputIndex];
                if (output.role == NetworkOutParameterRole::PayloadBuffer ||
                    output.role == NetworkOutParameterRole::HeaderBuffer)
                    contentOutputs.push_back(output);
            }
            if (contentOutputs.empty()) continue;
            producer.replyDecisionAnalysisAttempted = true;

            bool producerComplete = true;
            bool recoveredAnyOrigin = false;
            std::vector<std::pair<ApiReplyDecisionObservation, size_t>> candidates;
            for (const NetworkApiOutParameter& output : contentOutputs) {
                const auto argument = std::find_if(
                    producer.arguments.begin(), producer.arguments.end(),
                    [&](const ApiArgumentObservation& value) {
                        return value.index == output.argumentIndex;
                    });
                if (argument == producer.arguments.end()) continue;
                const OutputBufferOrigin origin = outputBufferOrigin(*argument);
                if (origin.compact.empty() && !origin.referencedAddressValid) continue;
                recoveredAnyOrigin = true;

                bool traceComplete = true;
                const std::vector<TracePoint> points = collectReachable(
                    producer.callVA, traceComplete);
                producerComplete = producerComplete && traceComplete;
                std::unordered_map<uint64_t, size_t> traceRank;
                for (const TracePoint& point : points) {
                    const Instruction& instruction =
                        g.blocks[point.block].insns[point.instruction];
                    traceRank.emplace(instruction.address, point.distance);
                }

                // Exact comparison helpers consuming the recovered reply buffer.
                for (size_t comparisonIndex = 0;
                     comparisonIndex < out.apiCalls.size(); ++comparisonIndex) {
                    if (comparisonIndex == producerIndex) continue;
                    const ApiCallObservation& comparisonCall = out.apiCalls[comparisonIndex];
                    if (!comparisonCall.callVAValid ||
                        !traceRank.count(comparisonCall.callVA))
                        continue;
                    const auto comparisonContract = exactEqualityCompareForName(
                        comparisonCall.resolvedName);
                    if (!comparisonContract) continue;
                    const ApiArgumentObservation* matchedArgument = nullptr;
                    const ApiArgumentObservation* expectedArgument = nullptr;
                    for (const ApiArgumentObservation& value : comparisonCall.arguments) {
                        if (!matchedArgument && argumentAliasesOutputOrigin(value, origin))
                            matchedArgument = &value;
                    }
                    if (!matchedArgument) continue;
                    for (const ApiArgumentObservation& value : comparisonCall.arguments) {
                        if (&value == matchedArgument) continue;
                        if (!value.stringLiteral.empty()) {
                            expectedArgument = &value;
                            break;
                        }
                        if (!expectedArgument &&
                            (!value.sourceExpression.empty() ||
                             !value.renderedValue.empty()))
                            expectedArgument = &value;
                    }

                    ApiReplyDecisionObservation decision;
                    decision.kind = ApiReplyDecisionKind::ComparisonCall;
                    decision.outputArgumentIndex = output.argumentIndex;
                    decision.outputRole = NetworkOutParameterRoleText(output.role);
                    decision.outputExpression = origin.expression;
                    decision.comparisonVA = comparisonCall.callVA;
                    decision.comparisonVAValid = true;
                    const auto compareLocation = instructionLocations.find(comparisonCall.callVA);
                    decision.comparisonInstruction = compareLocation == instructionLocations.end()
                        ? ("call " + comparisonCall.resolvedName)
                        : instructionText(g.blocks[compareLocation->second.first]
                                           .insns[compareLocation->second.second]);
                    if (expectedArgument) {
                        decision.expectedValue = !expectedArgument->stringLiteral.empty()
                            ? ("\"" + expectedArgument->stringLiteral + "\"")
                            : (!expectedArgument->sourceExpression.empty()
                                ? expectedArgument->sourceExpression
                                : expectedArgument->renderedValue);
                    }
                    decision.comparisonSummary = "reply " + decision.outputRole + " " +
                        (origin.expression.empty() ? std::string("buffer") : origin.expression) +
                        " is compared" + (decision.expectedValue.empty()
                            ? std::string() : " with " + decision.expectedValue) +
                        " by " + comparisonCall.resolvedName;

                    const Instruction* resultComparison = nullptr;
                    const Instruction* branch = nullptr;
                    equalityResultBranch(comparisonCall,
                        comparisonContract->equalityResult, producerComplete,
                        resultComparison, branch);
                    fillDecisionPaths(decision, branch, true, true,
                                      "reply content matches the compared value",
                                      "reply content differs from the compared value");
                    decision.evidence = network->dll + "!" + network->canonicalName +
                        " writes cataloged " + decision.outputRole + " argument " +
                        std::to_string(output.oneBasedOrdinal()) + "; " +
                        comparisonCall.resolvedName + " consumes the same recovered buffer origin";
                    if (resultComparison)
                        decision.evidence += "; " + instructionText(*resultComparison) +
                            " tests the comparison result";
                    if (branch)
                        decision.evidence += "; the adjacent conditional branch consumes those flags";
                    decision.confidence = branch
                        ? (decision.expectedValue.empty() ? 0.84f : 0.92f)
                        : (decision.expectedValue.empty() ? 0.64f : 0.72f);
                    candidates.push_back({ std::move(decision),
                        traceRank[comparisonCall.callVA] });
                }

                // Inline byte/field comparisons of the reply buffer or a value
                // loaded from it in the same block.
                for (const TracePoint& point : points) {
                    const Instruction& comparison =
                        g.blocks[point.block].insns[point.instruction];
                    if (comparison.mnemonic != "cmp" && comparison.mnemonic != "test")
                        continue;
                    const std::vector<std::string> operands = splitOps(comparison.operands);
                    if (operands.empty()) continue;
                    int matchedOperand = -1;
                    for (size_t operandIndex = 0; operandIndex < operands.size(); ++operandIndex) {
                        if (instructionReferencesOrigin(comparison, operands[operandIndex], origin,
                                                        point.block, point.instruction)) {
                            matchedOperand = static_cast<int>(operandIndex);
                            break;
                        }
                    }
                    if (matchedOperand < 0) continue;
                    const Instruction* branch = nearbyDecisionBranch(
                        point.block, point.instruction);
                    ApiReplyDecisionObservation decision;
                    decision.kind = ApiReplyDecisionKind::DirectComparison;
                    decision.outputArgumentIndex = output.argumentIndex;
                    decision.outputRole = NetworkOutParameterRoleText(output.role);
                    decision.outputExpression = origin.expression;
                    decision.comparisonVA = comparison.address;
                    decision.comparisonVAValid = true;
                    decision.comparisonInstruction = instructionText(comparison);
                    if (operands.size() == 2)
                        decision.expectedValue = operands[matchedOperand == 0 ? 1 : 0];
                    decision.comparisonSummary = "reply " + decision.outputRole + " is checked by `" +
                        decision.comparisonInstruction + "`";
                    const bool equalityComparison = comparison.mnemonic == "cmp" ||
                        (comparison.mnemonic == "test" && operands.size() == 2 &&
                         compactExpression(operands[0]) == compactExpression(operands[1]));
                    fillDecisionPaths(decision, branch, equalityComparison, true,
                                      comparison.mnemonic == "test"
                                        ? "tested reply value is zero"
                                        : "reply value matches the compared value",
                                      comparison.mnemonic == "test"
                                        ? "tested reply value is non-zero"
                                        : "reply value differs from the compared value");
                    decision.evidence = network->dll + "!" + network->canonicalName +
                        " writes cataloged " + decision.outputRole + " argument " +
                        std::to_string(output.oneBasedOrdinal()) + "; the comparison reads that recovered buffer origin";
                    if (branch)
                        decision.evidence += "; the adjacent conditional branch consumes the comparison flags";
                    decision.confidence = branch ? 0.84f : 0.66f;
                    candidates.push_back({ std::move(decision), point.distance });
                }
            }

            if (!recoveredAnyOrigin) {
                producerComplete = false;
                producer.replyDecisionIncompleteReason =
                    "cataloged reply buffer argument origin was not recovered";
            }
            std::stable_sort(candidates.begin(), candidates.end(),
                [](const auto& left, const auto& right) {
                    const bool leftBranch = left.first.decisionVAValid;
                    const bool rightBranch = right.first.decisionVAValid;
                    if (leftBranch != rightBranch) return leftBranch > rightBranch;
                    if (left.first.confidence != right.first.confidence)
                        return left.first.confidence > right.first.confidence;
                    if (left.second != right.second) return left.second < right.second;
                    return left.first.comparisonVA < right.first.comparisonVA;
                });
            std::unordered_set<std::string> seen;
            for (auto& candidate : candidates) {
                const std::string key = std::to_string(candidate.first.comparisonVA) + ":" +
                                        std::to_string(candidate.first.decisionVA) + ":" +
                                        std::to_string(candidate.first.outputArgumentIndex);
                if (!seen.insert(key).second) continue;
                if (producer.replyDecisions.size() >= 4) {
                    producerComplete = false;
                    if (producer.replyDecisionIncompleteReason.empty())
                        producer.replyDecisionIncompleteReason =
                            "reply comparison sink cap retained the four strongest candidates";
                    break;
                }
                producer.replyDecisions.push_back(std::move(candidate.first));
            }
            producer.replyDecisionsComplete = producerComplete;
            if (!producerComplete && producer.replyDecisionIncompleteReason.empty())
                producer.replyDecisionIncompleteReason =
                    "bounded reply-buffer CFG trace reached its instruction, block, or result limit";
        }

        // Fixed-output local input API -> exact comparator/inline check ->
        // adjacent decision branch. This deliberately shares only the bounded
        // traversal machinery with reply analysis; its evidence and results
        // remain a separate type so local input is never presented as a server
        // reply. Format-driven scanf-family contracts are not eligible here.
        constexpr size_t kMaxLocalValidationCalls = 256;
        constexpr size_t kMaxLocalInputProducers = 16;
        constexpr size_t kMaxLocalComparatorSinksPerProducer = 32;
        const size_t classifiedCallCount =
            (std::min)(out.apiCalls.size(), kMaxLocalValidationCalls);
        std::vector<std::optional<ValidationApiMatch>> validationCalls;
        validationCalls.reserve(classifiedCallCount);
        for (size_t callIndex = 0; callIndex < classifiedCallCount; ++callIndex)
            validationCalls.push_back(
                exactValidationApiForName(out.apiCalls[callIndex].resolvedName));
        const bool validationCallsTruncated =
            classifiedCallCount < out.apiCalls.size();
        if (validationCallsTruncated) {
            out.complete = false;
            const std::string reason =
                "validation call classification cap examined the first 256 named calls; local input decisions may be omitted";
            if (out.incompleteReason.empty()) out.incompleteReason = reason;
            else if (out.incompleteReason.find(reason) == std::string::npos)
                out.incompleteReason += "; " + reason;
        }
        auto appendLocalIncomplete = [](ApiCallObservation& call,
                                        const std::string& reason) {
            if (call.localInputDecisionIncompleteReason.empty())
                call.localInputDecisionIncompleteReason = reason;
            else if (call.localInputDecisionIncompleteReason.find(reason) ==
                     std::string::npos)
                call.localInputDecisionIncompleteReason += "; " + reason;
        };

        size_t localProducerCount = 0;
        for (size_t producerIndex = 0;
             producerIndex < classifiedCallCount; ++producerIndex) {
            ApiCallObservation& producer = out.apiCalls[producerIndex];
            if (!validationCalls[producerIndex] ||
                validationCalls[producerIndex]->kind !=
                    ValidationApiKind::InputProducer)
                continue;
            const ValidationApiMatch& producerMatch =
                *validationCalls[producerIndex];
            if (producerMatch.input.binding !=
                    ValidationInputBinding::FixedOutputArgument ||
                !producerMatch.input.outputArgumentIndexValid)
                continue;

            producer.localInputDecisionAnalysisAttempted = true;
            if (++localProducerCount > kMaxLocalInputProducers) {
                producer.localInputDecisionsComplete = false;
                appendLocalIncomplete(producer,
                    "local input producer cap retained the first 16 exact fixed-output producers");
                continue;
            }
            bool producerComplete = true;
            if (validationCallsTruncated) {
                producerComplete = false;
                appendLocalIncomplete(producer,
                    "validation call classification cap examined the first 256 named calls");
            }
            const uint32_t outputArgumentIndex =
                producerMatch.input.outputArgumentIndex;
            const auto outputArgument = std::find_if(
                producer.arguments.begin(), producer.arguments.end(),
                [&](const ApiArgumentObservation& value) {
                    return value.index == outputArgumentIndex;
                });
            OutputBufferOrigin origin;
            if (outputArgument != producer.arguments.end())
                origin = outputBufferOrigin(*outputArgument);
            const bool originRecovered = outputArgument != producer.arguments.end() &&
                (!origin.compact.empty() || origin.referencedAddressValid);
            if (!originRecovered) {
                producerComplete = false;
                appendLocalIncomplete(producer,
                    "cataloged local input buffer argument origin was not recovered");
            }

            std::vector<std::pair<ApiLocalInputDecisionObservation, size_t>> candidates;
            if (originRecovered) {
                bool traceComplete = true;
                const std::vector<TracePoint> points = collectReachable(
                    producer.callVA, traceComplete);
                producerComplete = producerComplete && traceComplete;
                std::unordered_map<uint64_t, size_t> traceRank;
                for (const TracePoint& point : points) {
                    const Instruction& instruction =
                        g.blocks[point.block].insns[point.instruction];
                    traceRank.emplace(instruction.address, point.distance);
                }

                // An exact later producer to the same output origin supersedes
                // this producer. Direct writes to that exact origin also break
                // content provenance. Distances are conservative across the
                // bounded reachable graph: ambiguity suppresses a claim rather
                // than choosing whichever path happened to be visited first.
                std::vector<size_t> replacementProducerDistances;
                for (size_t otherIndex = 0;
                     otherIndex < classifiedCallCount; ++otherIndex) {
                    if (otherIndex == producerIndex || !validationCalls[otherIndex] ||
                        validationCalls[otherIndex]->kind !=
                            ValidationApiKind::InputProducer)
                        continue;
                    const ValidationApiMatch& otherMatch =
                        *validationCalls[otherIndex];
                    if (otherMatch.input.binding !=
                            ValidationInputBinding::FixedOutputArgument ||
                        !otherMatch.input.outputArgumentIndexValid)
                        continue;
                    const ApiCallObservation& otherCall = out.apiCalls[otherIndex];
                    const auto distance = traceRank.find(otherCall.callVA);
                    if (!otherCall.callVAValid || distance == traceRank.end()) continue;
                    const auto otherOutput = std::find_if(
                        otherCall.arguments.begin(), otherCall.arguments.end(),
                        [&](const ApiArgumentObservation& value) {
                            return value.index ==
                                otherMatch.input.outputArgumentIndex;
                        });
                    if (otherOutput != otherCall.arguments.end() &&
                        argumentExactlyAliasesOutputOrigin(*otherOutput, origin))
                        replacementProducerDistances.push_back(distance->second);
                }

                std::vector<size_t> interveningWriteDistances;
                for (const TracePoint& point : points) {
                    const Instruction& instruction =
                        g.blocks[point.block].insns[point.instruction];
                    const std::vector<std::string> operands =
                        splitOps(instruction.operands);
                    if (!operands.empty() && writesMemFirstOp(instruction) &&
                        instructionExactlyReferencesOrigin(
                            instruction, operands.front(), origin,
                            point.block, point.instruction,
                            producer.callVA))
                        interveningWriteDistances.push_back(point.distance);
                }

                auto originStillFromProducer = [&](size_t sinkDistance) {
                    for (size_t distance : replacementProducerDistances) {
                        if (distance < sinkDistance) {
                            producerComplete = false;
                            appendLocalIncomplete(producer,
                                "a later exact fixed-output producer reaches the same origin before a candidate sink; stale attribution was suppressed");
                            return false;
                        }
                    }
                    for (size_t distance : interveningWriteDistances) {
                        if (distance < sinkDistance) {
                            producerComplete = false;
                            appendLocalIncomplete(producer,
                                "an intervening write reaches the exact local input origin before a candidate sink; content provenance was suppressed");
                            return false;
                        }
                    }
                    return true;
                };

                // Some exact producers (notably fgets/fgetws) document that a
                // successful return aliases the declared output pointer. Honor
                // that contract only through a bounded same-block register
                // lineage; a call or overwrite kills the alias.
                auto argumentAliasesProducerReturn = [&]
                    (const ApiCallObservation& sink,
                     const ApiArgumentObservation& argument) {
                    if (!producerMatch.input.returnValueAliasesOutput)
                        return false;
                    const auto producerLocation =
                        instructionLocations.find(producer.callVA);
                    const auto sinkLocation = instructionLocations.find(sink.callVA);
                    if (producerLocation == instructionLocations.end() ||
                        sinkLocation == instructionLocations.end() ||
                        producerLocation->second.first != sinkLocation->second.first ||
                        producerLocation->second.second >= sinkLocation->second.second)
                        return false;

                    const BasicBlock& block =
                        g.blocks[producerLocation->second.first];
                    std::unordered_set<std::string> returnAliases = { "rax" };
                    for (size_t instructionIndex =
                             producerLocation->second.second + 1;
                         instructionIndex < sinkLocation->second.second;
                         ++instructionIndex) {
                        const Instruction& instruction =
                            block.insns[instructionIndex];
                        const std::vector<std::string> operands =
                            splitOps(instruction.operands);
                        std::string copiedDestination;
                        if (instruction.mnemonic == "mov" && operands.size() == 2) {
                            const std::string source = canonReg(operands[1]);
                            const std::string destination = canonReg(operands[0]);
                            if (!source.empty() && !destination.empty() &&
                                returnAliases.count(source))
                                copiedDestination = destination;
                        }
                        const RW rw = classifyRW(instruction);
                        for (const std::string& written : rw.writes)
                            returnAliases.erase(written);
                        if (!copiedDestination.empty())
                            returnAliases.insert(copiedDestination);
                        if (returnAliases.empty()) break;
                    }

                    const std::string source = canonReg(
                        argument.sourceExpression.empty()
                            ? argument.renderedValue
                            : argument.sourceExpression);
                    const std::string abiRegister = canonReg(argument.abiLocation);
                    return (!source.empty() && returnAliases.count(source)) ||
                           (!abiRegister.empty() &&
                            returnAliases.count(abiRegister));
                };

                // Only exact cataloged equality comparators are eligible. The
                // producer origin must occupy one of the comparator's declared
                // data arguments, and the opposite argument must be a resolver-
                // proven literal. Length/format arguments can never substitute.
                size_t comparatorSinksExamined = 0;
                for (size_t comparisonIndex = 0;
                     comparisonIndex < classifiedCallCount; ++comparisonIndex) {
                    if (comparisonIndex == producerIndex) continue;
                    const ApiCallObservation& comparisonCall =
                        out.apiCalls[comparisonIndex];
                    if (!comparisonCall.callVAValid ||
                        !traceRank.count(comparisonCall.callVA))
                        continue;
                    if (!validationCalls[comparisonIndex] ||
                        validationCalls[comparisonIndex]->kind !=
                            ValidationApiKind::EqualityComparator)
                        continue;
                    if (++comparatorSinksExamined >
                        kMaxLocalComparatorSinksPerProducer) {
                        producerComplete = false;
                        appendLocalIncomplete(producer,
                            "local comparator sink cap examined the first 32 reachable exact comparators");
                        break;
                    }
                    const ValidationApiMatch& comparatorMatch =
                        *validationCalls[comparisonIndex];
                    if (!validationEncodingsCompatible(producerMatch.input.encoding,
                                                       comparatorMatch.comparator.encoding))
                        continue;

                    const auto argumentAt = [&](uint32_t index)
                            -> const ApiArgumentObservation* {
                        const auto found = std::find_if(
                            comparisonCall.arguments.begin(), comparisonCall.arguments.end(),
                            [&](const ApiArgumentObservation& value) {
                                return value.index == index;
                            });
                        return found == comparisonCall.arguments.end() ? nullptr : &*found;
                    };
                    const ApiArgumentObservation* left = argumentAt(
                        comparatorMatch.comparator.leftArgumentIndex);
                    const ApiArgumentObservation* right = argumentAt(
                        comparatorMatch.comparator.rightArgumentIndex);
                    if (!left || !right) continue;

                    // Bounded comparators can report equality without reading
                    // either buffer when their length is zero. Retain each
                    // recovered bound so the expected value below describes
                    // only the bytes/code units the call can actually inspect.
                    struct RecoveredComparatorLength {
                        uint64_t count = 0;
                        bool nullTerminated = false;
                    };
                    std::array<RecoveredComparatorLength,
                               kValidationComparatorMaxLengthArguments>
                        recoveredLengths{};
                    bool lengthsProveComparison = true;
                    for (uint8_t lengthIndex = 0;
                         lengthIndex < comparatorMatch.comparator.lengthArgumentCount;
                         ++lengthIndex) {
                        const ApiArgumentObservation* length = argumentAt(
                            comparatorMatch.comparator
                                .lengthArgumentIndices[lengthIndex]);
                        if (!length || !length->immediateValid ||
                            length->immediate == 0) {
                            lengthsProveComparison = false;
                            break;
                        }
                        if (comparatorMatch.comparator.lengthArgumentCount == 2) {
                            // The catalog's two-length Win32 comparators use
                            // signed 32-bit character counts; -1 means the
                            // corresponding input is null terminated.
                            const int32_t signedCount = static_cast<int32_t>(
                                length->immediate & 0xFFFFFFFFu);
                            if (signedCount == -1) {
                                recoveredLengths[lengthIndex].nullTerminated = true;
                            } else if (signedCount <= 0) {
                                lengthsProveComparison = false;
                                break;
                            } else {
                                recoveredLengths[lengthIndex].count =
                                    static_cast<uint64_t>(signedCount);
                            }
                        } else {
                            recoveredLengths[lengthIndex].count =
                                length->immediate;
                        }
                    }
                    if (!lengthsProveComparison) continue;

                    const bool leftReturnAlias =
                        argumentAliasesProducerReturn(comparisonCall, *left);
                    const bool rightReturnAlias =
                        argumentAliasesProducerReturn(comparisonCall, *right);
                    const bool leftMatches =
                        argumentExactlyAliasesOutputOrigin(*left, origin) ||
                        leftReturnAlias;
                    const bool rightMatches =
                        argumentExactlyAliasesOutputOrigin(*right, origin) ||
                        rightReturnAlias;
                    if (leftMatches == rightMatches) continue;
                    const ApiArgumentObservation* expected = leftMatches ? right : left;
                    if (expected->stringLiteral.empty()) continue;

                    bool boundedExpectedValue = false;
                    uint64_t expectedUnitCount = 0;
                    if (comparatorMatch.comparator.lengthArgumentCount == 1) {
                        boundedExpectedValue = true;
                        expectedUnitCount = recoveredLengths[0].count;
                    } else if (comparatorMatch.comparator.lengthArgumentCount == 2) {
                        // Catalog order pairs the first/second length with the
                        // declared left/right data argument respectively.
                        const size_t expectedLengthIndex = leftMatches ? 1 : 0;
                        if (!recoveredLengths[expectedLengthIndex].nullTerminated) {
                            boundedExpectedValue = true;
                            expectedUnitCount =
                                recoveredLengths[expectedLengthIndex].count;
                        }
                    }
                    std::optional<std::string> boundedExpectedDisplay;
                    if (boundedExpectedValue) {
                        if (expectedUnitCount >
                            static_cast<uint64_t>((std::numeric_limits<size_t>::max)()))
                            continue;
                        boundedExpectedDisplay = quotedAsciiPrefix(
                            expected->stringLiteral,
                            static_cast<size_t>(expectedUnitCount));
                        if (!boundedExpectedDisplay) continue;
                    }
                    if (!originStillFromProducer(
                            traceRank.at(comparisonCall.callVA)))
                        continue;

                    int64_t equalityResult = 0;
                    bool zeroConditionMeansMatch = true;
                    switch (comparatorMatch.comparator.equalityRule) {
                    case ValidationEqualityRule::ZeroIsEqual:
                        equalityResult = 0;
                        break;
                    case ValidationEqualityRule::NonZeroIsEqual:
                        equalityResult = 0;
                        zeroConditionMeansMatch = false;
                        break;
                    case ValidationEqualityRule::ExactValueIsEqual:
                        equalityResult = comparatorMatch.comparator.equalityValue;
                        break;
                    }

                    const Instruction* resultComparison = nullptr;
                    const Instruction* branch = nullptr;
                    equalityResultBranch(comparisonCall, equalityResult,
                        producerComplete, resultComparison, branch);
                    if (!branch) continue;

                    ApiLocalInputDecisionObservation decision;
                    decision.kind = ApiLocalInputDecisionKind::ComparisonCall;
                    decision.outputArgumentIndex = outputArgumentIndex;
                    decision.inputEncoding = ValidationDataEncodingText(
                        producerMatch.input.encoding);
                    decision.outputExpression = origin.expression;
                    decision.comparatorName = comparatorMatch.dll + "!" +
                                              comparatorMatch.canonicalName;
                    decision.comparatorCallVA = comparisonCall.callVA;
                    decision.comparatorCallVAValid = true;
                    decision.comparisonVA = comparisonCall.callVA;
                    decision.comparisonVAValid = true;
                    const auto compareLocation = instructionLocations.find(
                        comparisonCall.callVA);
                    decision.comparisonInstruction =
                        compareLocation == instructionLocations.end()
                        ? ("call " + comparisonCall.resolvedName)
                        : instructionText(g.blocks[compareLocation->second.first]
                                           .insns[compareLocation->second.second]);
                    if (boundedExpectedDisplay) {
                        decision.expectedValue = *boundedExpectedDisplay +
                            " (first " + std::to_string(expectedUnitCount) +
                            (comparatorMatch.comparator.encoding ==
                                ValidationDataEncoding::WideText
                                ? " UTF-16 code unit(s))"
                                : " byte(s))");
                    } else {
                        decision.expectedValue = "\"" + expected->stringLiteral;
                        if (expected->stringLiteralTruncated)
                            decision.expectedValue +=
                                "...\" (truncated resolver prefix)";
                        else
                            decision.expectedValue += "\"";
                    }
                    decision.comparisonSummary = "local input " +
                        (origin.expression.empty() ? std::string("buffer") : origin.expression) +
                        " is compared with " + decision.expectedValue + " by " +
                        decision.comparatorName;
                    fillDecisionPaths(decision, branch, true,
                        zeroConditionMeansMatch,
                        "local input matches the expected value",
                        "local input differs from the expected value");
                    decision.evidence = producerMatch.dll + "!" +
                        producerMatch.canonicalName + " writes fixed output argument " +
                        std::to_string(outputArgumentIndex + 1) + "; " +
                        decision.comparatorName +
                        " consumes that exact recovered output origin and a resolver-proven literal";
                    if (!boundedExpectedDisplay && expected->stringLiteralTruncated)
                        decision.evidence +=
                            " prefix (the resolver text exceeded the 40-byte preview cap)";
                    if ((leftMatches && leftReturnAlias) ||
                        (rightMatches && rightReturnAlias))
                        decision.evidence +=
                            "; the cataloged producer return aliases its output and a bounded same-block register lineage reaches the comparator argument";
                    if (boundedExpectedDisplay)
                        decision.evidence +=
                            "; expected value is limited to the exact recovered nonzero comparison length of " +
                            std::to_string(expectedUnitCount) +
                            (comparatorMatch.comparator.encoding ==
                                ValidationDataEncoding::WideText
                                ? " UTF-16 code unit(s)"
                                : " byte(s)");
                    else if (comparatorMatch.comparator.lengthArgumentCount)
                        decision.evidence +=
                            "; every catalog-declared comparison length is a recovered nonzero immediate";
                    if (resultComparison)
                        decision.evidence += "; " + instructionText(*resultComparison) +
                            " tests the comparator result";
                    decision.evidence +=
                        "; bounded same-function evidence does not prove this is the final authorization gate";
                    decision.confidence = 0.94f;
                    candidates.push_back({ std::move(decision),
                        traceRank[comparisonCall.callVA] });
                }

                // Inline checks are narrower still: exact memory-origin equality
                // or a value loaded from that exact origin, followed immediately
                // by a conditional branch. Nearby stack slots are not aliases.
                for (const TracePoint& point : points) {
                    const Instruction& comparison =
                        g.blocks[point.block].insns[point.instruction];
                    if (comparison.mnemonic != "cmp" && comparison.mnemonic != "test")
                        continue;
                    const std::vector<std::string> operands = splitOps(comparison.operands);
                    if (operands.size() != 2) continue;
                    int matchedOperand = -1;
                    for (size_t operandIndex = 0; operandIndex < operands.size(); ++operandIndex) {
                        if (instructionExactlyReferencesOrigin(
                                comparison, operands[operandIndex], origin,
                                point.block, point.instruction,
                                producer.callVA)) {
                            matchedOperand = static_cast<int>(operandIndex);
                            break;
                        }
                    }
                    if (matchedOperand < 0) continue;
                    const int expectedOperand = matchedOperand == 0 ? 1 : 0;
                    if (comparison.mnemonic == "cmp" &&
                        instructionExactlyReferencesOrigin(
                            comparison, operands[expectedOperand], origin,
                            point.block, point.instruction,
                            producer.callVA))
                        continue;
                    const bool zeroTest = comparison.mnemonic == "test" &&
                        compactExpression(operands[0]) == compactExpression(operands[1]);
                    if (comparison.mnemonic == "test" && !zeroTest) continue;
                    const Instruction* branch = nearbyDecisionBranch(
                        point.block, point.instruction);
                    if (!branch) continue;
                    if (!originStillFromProducer(point.distance)) continue;

                    ApiLocalInputDecisionObservation decision;
                    decision.kind = ApiLocalInputDecisionKind::DirectComparison;
                    decision.outputArgumentIndex = outputArgumentIndex;
                    decision.inputEncoding = ValidationDataEncodingText(
                        producerMatch.input.encoding);
                    decision.outputExpression = origin.expression;
                    decision.comparisonVA = comparison.address;
                    decision.comparisonVAValid = true;
                    decision.comparisonInstruction = instructionText(comparison);
                    decision.expectedValue = zeroTest ? "zero" : operands[expectedOperand];
                    decision.comparisonSummary = "local input is checked by `" +
                        decision.comparisonInstruction + "`";
                    fillDecisionPaths(decision, branch, true, true,
                        zeroTest ? "tested local input value is zero"
                                 : "local input matches the compared value",
                        zeroTest ? "tested local input value is non-zero"
                                 : "local input differs from the compared value");
                    decision.evidence = producerMatch.dll + "!" +
                        producerMatch.canonicalName + " writes fixed output argument " +
                        std::to_string(outputArgumentIndex + 1) +
                        "; the inline comparison reads that exact recovered output origin" +
                        "; bounded same-function evidence does not prove this is the final authorization gate";
                    decision.confidence = 0.88f;
                    candidates.push_back({ std::move(decision), point.distance });
                }
            }

            std::stable_sort(candidates.begin(), candidates.end(),
                [](const auto& left, const auto& right) {
                    if (left.first.confidence != right.first.confidence)
                        return left.first.confidence > right.first.confidence;
                    if (left.second != right.second) return left.second < right.second;
                    return left.first.comparisonVA < right.first.comparisonVA;
                });
            std::unordered_set<std::string> seen;
            for (auto& candidate : candidates) {
                const std::string key = std::to_string(candidate.first.comparisonVA) + ":" +
                                        std::to_string(candidate.first.decisionVA) + ":" +
                                        std::to_string(candidate.first.outputArgumentIndex);
                if (!seen.insert(key).second) continue;
                if (producer.localInputDecisions.size() >= 4) {
                    producerComplete = false;
                    appendLocalIncomplete(producer,
                        "local input result cap retained the four strongest comparison candidates");
                    break;
                }
                producer.localInputDecisions.push_back(std::move(candidate.first));
            }
            producer.localInputDecisionsComplete = producerComplete;
            if (!producerComplete && producer.localInputDecisionIncompleteReason.empty())
                appendLocalIncomplete(producer,
                    "bounded local-input CFG trace reached its instruction, block, or state limit");
        }
    }

    // ---- 7) Loop-body pattern scans -----------------------------------------
    for (const LoopInfo& L : loops) {
        int xorMem = 0, xorImm = 0, memWrite = 0, memRead = 0, idxStep = 0, mix = 0, accAdd = 0, byteCmp = 0;
        std::vector<uint64_t> ev;
        int insnCount = 0;
        for (int bi : order) {
            const BasicBlock& b = g.blocks[bi];
            if (b.start < L.lo || b.start >= L.hi) continue;
            for (const Instruction& in : b.insns) {
                ++insnCount;
                const std::string& m = in.mnemonic;
                std::vector<std::string> ops = splitOps(in.operands);
                bool hasMem = in.operands.find('[') != std::string::npos;
                if (m == "xor" && ops.size() == 2) {
                    if (hasMem) { ++xorMem; ev.push_back(in.address); }
                    else {
                        int64_t imm = 0;
                        if (canonReg(ops[1]).empty() && parseImm(ops[1], imm) && imm != 0) { ++xorImm; ev.push_back(in.address); }
                    }
                }
                if (hasMem && writesMemFirstOp(in)) ++memWrite;
                if (hasMem && !writesMemFirstOp(in) && m != "lea" && m != "cmp") ++memRead;
                if (m == "inc" || (m == "add" && ops.size() == 2 && [&]{ int64_t v; return parseImm(ops[1], v) && v >= 1 && v <= 8; }()))
                    ++idxStep;
                if (m == "lea" && ops.size() == 2) {
                    MemOp lm = parseMem(ops[1]);
                    if (lm.ok && lm.base == canonReg(ops[0]) && lm.hasDisp && lm.disp >= 1 && lm.disp <= 8) ++idxStep;
                }
                if (m == "rol" || m == "ror" || m == "shl" || m == "shr" || m == "sar" || m == "imul") { ++mix; ev.push_back(in.address); }
                if ((m == "add" || m == "adc") && hasMem && ops.size() == 2 && ops[1].find('[') != std::string::npos)
                    { ++accAdd; ev.push_back(in.address); }
                if ((m == "add" || m == "adc") && ops.size() == 2 && !canonReg(ops[1]).empty()) ++accAdd;
                if (m == "cmp" && toLower(in.operands).find("byte") != std::string::npos && hasMem)
                    { ++byteCmp; ev.push_back(in.address); }
                if (in.isRepString) { ++memRead; ++memWrite; }
            }
        }
        auto evStr = [&](const char* what) {
            std::string s = std::string(what) + " inside loop " + vaHex(L.lo) + "-" + vaHex(L.hi) + ":";
            int shown = 0;
            for (uint64_t a : ev) { if (shown++ == 6) { s += " ..."; break; } s += " " + vaHex(a); }
            return s;
        };
        uint64_t hdrVA = 0;
        for (int bi : order) if (g.blocks[bi].start == L.lo && !g.blocks[bi].insns.empty()) { hdrVA = g.blocks[bi].insns.front().address; break; }
        if ((xorMem >= 1 && idxStep >= 1) || (xorImm >= 1 && memRead >= 1 && memWrite >= 1 && idxStep >= 1)) {
            float conf = 0.5f + (xorMem && memWrite ? 0.15f : 0.0f);
            note(hdrVA, NoteKind::Pattern, "XOR decode/encode loop?",
                 evStr("xor over advancing memory"), conf);
        } else if (mix >= 1 && (xorMem + xorImm + accAdd) >= 1 && memRead >= 1 && idxStep >= 1) {
            note(hdrVA, NoteKind::Pattern, "checksum/hash-like loop?",
                 evStr("shift/rotate/multiply mixed with accumulation over memory"), 0.5f);
        } else if (byteCmp >= 1 && idxStep >= 1) {
            note(hdrVA, NoteKind::Pattern, "byte-compare loop (string/memory comparison?)",
                 evStr("byte-wide compares over advancing memory"), 0.5f);
        }
        (void)insnCount;
    }

    // ---- 8) Function-level API-set patterns ----------------------------------
    {
        struct ApiHit { std::string name; uint64_t va; };
        std::vector<ApiHit> calls;
        bool hasRdtsc = false; uint64_t rdtscVA = 0;
        for (const FlatInsn& f : flat) {
            const Instruction& in = *f.in;
            if (in.isCall) {
                std::string nm = callName(in);
                if (!nm.empty()) calls.push_back({ toLower(nm), in.address });
            }
            if (in.mnemonic == "rdtsc" || in.mnemonic == "rdtscp") { hasRdtsc = true; rdtscVA = in.address; }
        }
        auto findCalls = [&](std::initializer_list<const char*> keys, std::vector<const ApiHit*>& hits) {
            for (const ApiHit& c : calls)
                for (const char* k : keys)
                    if (c.name.find(k) != std::string::npos) { hits.push_back(&c); break; }
        };
        auto emitApiPattern = [&](const char* text, std::initializer_list<const char*> keys, float conf) {
            std::vector<const ApiHit*> hits;
            findCalls(keys, hits);
            if (hits.empty()) return;
            std::string ev = "calls:";
            int shown = 0;
            for (const ApiHit* h : hits) { if (shown++ == 5) { ev += " ..."; break; } ev += " " + h->name + "@" + vaHex(h->va); }
            functionNote(NoteKind::Pattern, text, ev, conf);
        };
        auto networkApiFor = [](const std::string& qualified)
                -> std::optional<NetworkApiMatch> {
            size_t separator = qualified.rfind('!');
            if (separator == std::string::npos) separator = qualified.rfind('.');
            if (separator == std::string::npos || separator == 0 ||
                separator + 1 >= qualified.size())
                return std::nullopt; // DLL identity is required for an exact match
            return LookupNetworkApi(std::string_view(qualified).substr(0, separator),
                                    std::string_view(qualified).substr(separator + 1));
        };
        auto emitNetworkPattern = [&] {
            std::vector<std::pair<const ApiHit*, NetworkApiMatch>> hits;
            for (const ApiHit& call : calls)
                if (auto match = networkApiFor(call.name))
                    hits.push_back({ &call, std::move(*match) });
            if (hits.empty()) return;
            std::string evidence = "exact DLL-aware network calls:";
            size_t shown = 0;
            for (const auto& [call, match] : hits) {
                if (shown++ == 5) { evidence += " ..."; break; }
                evidence += " " + match.dll + "!" + match.canonicalName + "@" + vaHex(call->va);
            }
            functionNote(NoteKind::Pattern, "network I/O", evidence, 0.70f);
        };
        emitApiPattern("reads user input", { "readconsole", "scanf", "fgets", "getchar", "_getch",
                       "getwindowtext", "getdlgitemtext", "readline", "istream" }, 0.65f);
        emitApiPattern("polls keyboard/mouse state (input handler?)",
                       { "getasynckeystate", "getkeystate", "getkeyboardstate", "getcursorpos" }, 0.6f);
        emitApiPattern("performs string/memory comparison",
                       { "strcmp", "strncmp", "stricmp", "memcmp", "wcscmp", "lstrcmp", "comparestring" }, 0.7f);
        emitApiPattern("opens/reads files", { "createfile", "fopen", "_wfopen", "openfile", "fread" }, 0.6f);
        emitNetworkPattern();
        emitApiPattern("reads timers (frame pacing / timing / anti-debug?)",
                       { "gettickcount", "queryperformancecounter", "timegettime" }, 0.55f);
        emitApiPattern("registers a callback/handler",
                       { "setwindowshookex", "registerclass", "settimer", "createthread", "atexit",
                         "signal", "setunhandledexceptionfilter", "setconsolectrlhandler" }, 0.6f);
        emitApiPattern("Windows message pump (UI/render/update loop candidate?)",
                       { "peekmessage", "getmessage", "dispatchmessage" }, !loops.empty() ? 0.6f : 0.45f);
        if (hasRdtsc)
            functionNote(NoteKind::Pattern,
                         "reads the CPU timestamp counter (timing/anti-debug?)",
                         "rdtsc at " + vaHex(rdtscVA), 0.6f);
        // Config/save file loading: file API + a referenced path-looking string.
        {
            std::vector<const ApiHit*> fileHits;
            findCalls({ "createfile", "fopen", "_wfopen" }, fileHits);
            if (!fileHits.empty() && opt.stringFor) {
                static const char* kExt[] = { ".ini", ".cfg", ".json", ".xml", ".dat", ".sav", ".bin",
                                              ".txt", ".db", ".cfg", ".conf", ".properties", ".yml" };
                for (const FlatInsn& f : flat) {
                    uint64_t ref = 0;
                    bool hasRef = TryGetInstrDataRef(*f.in, ref);
                    if (!hasRef) hasRef = TryGetInstrImmRef(*f.in, ref);
                    if (!hasRef) continue;
                    std::string s = toLower(stringFor(ref));
                    if (s.empty()) continue;
                    for (const char* e : kExt) {
                        if (s.size() > std::strlen(e) && s.rfind(e) == s.size() - std::strlen(e)) {
                            functionNote(NoteKind::Pattern,
                                         "loads config/data file \"" + stringFor(ref) + "\"?",
                                         "file-open API called in this function and \"" + stringFor(ref) +
                                         "\" is referenced at " + vaHex(f.in->address), 0.55f);
                            e = nullptr; break;
                        }
                    }
                    if (out.notes.size() > 400) break;   // sanity cap
                }
            }
        }
    }

    // ---- 9) Typed formal-field and function-return observations ------------
    // These facts are deliberately separate from the display-oriented field
    // offsets and notes above. They use CFG must-data-flow and retain exact
    // root/operand identities for whole-program authorization analysis.
    {
        using BlockIndex = size_t;
        constexpr BlockIndex kNoBlock = (std::numeric_limits<BlockIndex>::max)();
        BlockIndex entryBlock = kNoBlock;
        for (BlockIndex index = 0; index < g.blocks.size(); ++index) {
            if (g.blocks[index].start == g.funcStart) {
                entryBlock = index;
                break;
            }
        }
        const bool entryExact = entryBlock != kNoBlock;
        if (!entryExact) entryBlock = static_cast<BlockIndex>(order.front());

        struct FormalRoot {
            uint32_t parameter = 0;
            int64_t bias = 0;
            std::string abiLocation;
        };
        auto sameRoot = [](const FormalRoot& left, const FormalRoot& right) {
            return left.parameter == right.parameter && left.bias == right.bias &&
                   left.abiLocation == right.abiLocation;
        };
        using FormalState = std::map<std::string, FormalRoot>;

        auto transferFormal = [&](FormalState& state, const Instruction& in) {
            if (InstructionIsCall(in)) {
                static const char* kVolatile[] = {
                    "rax", "rcx", "rdx", "r8", "r9", "r10", "r11"
                };
                for (const char* reg : kVolatile) state.erase(reg);
                return;
            }

            std::string definedRegister;
            bool definitionModelled = false;
            const uint16_t pointerWidth = x64 ? 64 : 32;
            if (!in.typedOperands.empty()) {
                if (in.typedOperands[0].kind == OperandKind::Register &&
                    OperandWrites(in.typedOperands[0].access)) {
                    const TypedOperand& destination = in.typedOperands[0];
                    definedRegister = canonReg(destination.registerName);
                    const uint16_t destinationWidth = destination.widthBits
                        ? destination.widthBits
                        : registerWidthBits(destination.registerName, x64);
                    if (!definedRegister.empty() && in.mnemonic == "mov" &&
                        in.typedOperands.size() >= 2 &&
                        in.typedOperands[1].kind == OperandKind::Register) {
                        const TypedOperand& source = in.typedOperands[1];
                        const std::string sourceRegister = canonReg(source.registerName);
                        const uint16_t sourceWidth = source.widthBits
                            ? source.widthBits
                            : registerWidthBits(source.registerName, x64);
                        if (destinationWidth >= pointerWidth && sourceWidth >= pointerWidth) {
                            const auto found = state.find(sourceRegister);
                            if (found != state.end()) state[definedRegister] = found->second;
                            else state.erase(definedRegister);
                            definitionModelled = true;
                        }
                    } else if (!definedRegister.empty() && in.mnemonic == "lea" &&
                               in.typedOperands.size() >= 2 &&
                               in.typedOperands[1].kind == OperandKind::Memory &&
                               destinationWidth >= pointerWidth) {
                        const TypedOperand& source = in.typedOperands[1];
                        const std::string sourceRegister = canonReg(source.baseRegister);
                        if (canonReg(source.indexRegister).empty() && !source.pcRelative) {
                            const auto found = state.find(sourceRegister);
                            const int64_t displacement = source.displacementValid
                                                       ? source.displacement : 0;
                            int64_t adjusted = 0;
                            if (found != state.end() &&
                                checkedAddSigned(found->second.bias, displacement, adjusted)) {
                                FormalRoot root = found->second;
                                root.bias = adjusted;
                                state[definedRegister] = std::move(root);
                            } else {
                                state.erase(definedRegister);
                            }
                            definitionModelled = true;
                        }
                    }
                }
            } else {
                // Compatibility for hand-authored unit fixtures. Production
                // decoders reach the typed path above.
                const std::vector<std::string> operands = splitOps(in.operands);
                if (!operands.empty()) definedRegister = canonReg(operands[0]);
                if (!definedRegister.empty() && operands.size() >= 2 &&
                    in.mnemonic == "mov") {
                    const std::string sourceRegister = canonReg(operands[1]);
                    if (registerWidthBits(operands[0], x64) >= pointerWidth &&
                        registerWidthBits(operands[1], x64) >= pointerWidth) {
                        const auto found = state.find(sourceRegister);
                        if (found != state.end()) state[definedRegister] = found->second;
                        else state.erase(definedRegister);
                        definitionModelled = true;
                    }
                } else if (!definedRegister.empty() && operands.size() >= 2 &&
                           in.mnemonic == "lea" &&
                           registerWidthBits(operands[0], x64) >= pointerWidth) {
                    const MemOp source = parseMem(operands[1]);
                    if (source.ok && source.index.empty()) {
                        const auto found = state.find(source.base);
                        const int64_t displacement = source.hasDisp ? source.disp : 0;
                        int64_t adjusted = 0;
                        if (found != state.end() &&
                            checkedAddSigned(found->second.bias, displacement, adjusted)) {
                            FormalRoot root = found->second;
                            root.bias = adjusted;
                            state[definedRegister] = std::move(root);
                        } else {
                            state.erase(definedRegister);
                        }
                        definitionModelled = true;
                    }
                }
            }

            const RW effects = classifyRW(in);
            for (const std::string& written : effects.writes) {
                if (!definitionModelled || written != definedRegister)
                    state.erase(written);
            }
        };

        auto mergeFormalState = [&](FormalState& destination,
                                    const FormalState& incoming) {
            bool changed = false;
            for (auto current = destination.begin(); current != destination.end();) {
                const auto other = incoming.find(current->first);
                if (other == incoming.end() || !sameRoot(current->second, other->second)) {
                    current = destination.erase(current);
                    changed = true;
                } else {
                    ++current;
                }
            }
            return changed;
        };

        std::vector<FormalState> formalIn(g.blocks.size());
        std::vector<bool> formalReached(g.blocks.size(), false);
        FormalState entryState;
        if (x64) {
            entryState.emplace("rcx", FormalRoot{0, 0, "rcx"});
            entryState.emplace("rdx", FormalRoot{1, 0, "rdx"});
            entryState.emplace("r8",  FormalRoot{2, 0, "r8"});
            entryState.emplace("r9",  FormalRoot{3, 0, "r9"});
        }
        formalIn[entryBlock] = std::move(entryState);
        formalReached[entryBlock] = true;
        std::deque<BlockIndex> formalWork{entryBlock};
        constexpr size_t kMaxDataFlowSteps = 65536;
        constexpr size_t kStepsPerBlock = 32;
        const size_t scaledDataFlowBudget =
            g.blocks.size() > kMaxDataFlowSteps / kStepsPerBlock
                ? kMaxDataFlowSteps
                : g.blocks.size() * kStepsPerBlock;
        const size_t dataFlowBudget = (std::max)(
            static_cast<size_t>(64), scaledDataFlowBudget);
        size_t formalSteps = 0;
        bool formalComplete = entryExact;
        std::string formalIncompleteReason = entryExact
            ? std::string()
            : "CFG has no block at the declared function entry";
        while (!formalWork.empty() && formalSteps++ < dataFlowBudget) {
            const BlockIndex blockIndex = formalWork.front();
            formalWork.pop_front();
            FormalState outgoing = formalIn[blockIndex];
            for (const Instruction& instruction : g.blocks[blockIndex].insns)
                transferFormal(outgoing, instruction);
            for (BlockIndex successor : g.blocks[blockIndex].succ) {
                if (successor >= g.blocks.size()) {
                    formalComplete = false;
                    formalIncompleteReason = "CFG contains an invalid successor index";
                    continue;
                }
                bool changed = false;
                if (!formalReached[successor]) {
                    formalReached[successor] = true;
                    formalIn[successor] = outgoing;
                    changed = true;
                } else {
                    changed = mergeFormalState(formalIn[successor], outgoing);
                }
                if (changed) formalWork.push_back(successor);
            }
        }
        if (!formalWork.empty()) {
            formalComplete = false;
            formalIncompleteReason =
                "formal-parameter provenance exceeded its bounded step limit";
        }

        auto accessKind = [](bool reads, bool writes) {
            if (reads && writes) return ObjectFieldAccessKind::ReadWrite;
            return writes ? ObjectFieldAccessKind::Write
                          : ObjectFieldAccessKind::Read;
        };
        constexpr size_t kMaxFieldAccessObservations = 4096;
        constexpr size_t kMaxDirectCallFormalBindings = 4096;
        bool fieldCollectionComplete = formalComplete && g.complete;
        std::string fieldCollectionIncompleteReason = formalIncompleteReason;
        if (!g.complete) {
            fieldCollectionIncompleteReason = g.incompleteReason.empty()
                ? "CFG is incomplete"
                : "CFG is incomplete: " + g.incompleteReason;
        }
        bool bindingCollectionActive = formalComplete && g.complete && x64 &&
                                       static_cast<bool>(opt.isInternalFunction);
        bool bindingCollectionComplete = bindingCollectionActive &&
                                         opt.internalFunctionMembershipComplete;
        std::string bindingCollectionIncompleteReason;
        if (!formalComplete) {
            bindingCollectionIncompleteReason = formalIncompleteReason.empty()
                ? "formal-parameter provenance is incomplete"
                : formalIncompleteReason;
        } else if (!g.complete) {
            bindingCollectionIncompleteReason = g.incompleteReason.empty()
                ? "CFG is incomplete"
                : "CFG is incomplete: " + g.incompleteReason;
        } else if (!x64) {
            bindingCollectionIncompleteReason =
                "exact formal-root call bindings are currently supported only for x64";
        } else if (!opt.isInternalFunction) {
            bindingCollectionIncompleteReason =
                "exact internal-function membership classifier was not supplied";
        } else if (!opt.internalFunctionMembershipComplete) {
            bindingCollectionIncompleteReason =
                "internal-function membership classifier scope was incomplete";
        }
        if ((fieldCollectionComplete || bindingCollectionActive) && x64) {
            for (int orderedBlock : order) {
                const BlockIndex blockIndex = static_cast<BlockIndex>(orderedBlock);
                if (!formalReached[blockIndex]) continue;
                FormalState state = formalIn[blockIndex];
                for (const Instruction& instruction : g.blocks[blockIndex].insns) {
                    if (bindingCollectionActive &&
                        InstructionIsCall(instruction)) {
                        uint64_t directTarget = 0;
                        bool exactDirectTarget = false;
                        if (instruction.flow.kind == FlowKind::DirectCall &&
                            instruction.flow.directTargetValid) {
                            directTarget = instruction.flow.directTarget;
                            exactDirectTarget = true;
                        } else if (instruction.flow.kind == FlowKind::None &&
                                   instruction.isCall &&
                                   instruction.branchTargetValid) {
                            directTarget = instruction.branchTarget;
                            exactDirectTarget = true;
                        }
                        if (exactDirectTarget) {
                            bool internalTarget = false;
                            try {
                                internalTarget = opt.isInternalFunction(directTarget);
                            } catch (...) {
                                bindingCollectionActive = false;
                                bindingCollectionComplete = false;
                                bindingCollectionIncompleteReason =
                                    "internal-function membership classifier failed";
                            }
                            if (bindingCollectionActive && internalTarget) {
                                for (uint32_t argumentIndex = 0;
                                     argumentIndex < 4; ++argumentIndex) {
                                    const std::string argumentRegister =
                                        kArgRegs64[argumentIndex];
                                    const auto root = state.find(argumentRegister);
                                    if (root == state.end() ||
                                        root->second.bias != 0)
                                        continue;
                                    if (out.directCallFormalBindings.size() >=
                                        kMaxDirectCallFormalBindings) {
                                        bindingCollectionActive = false;
                                        bindingCollectionComplete = false;
                                        bindingCollectionIncompleteReason =
                                            "direct-call formal-binding observation cap reached";
                                        break;
                                    }
                                    DirectCallFormalBindingObservation observation;
                                    observation.callerFunctionVA = g.funcStart;
                                    observation.callerFunctionVAValid = true;
                                    observation.callerRootParameterIndex =
                                        root->second.parameter;
                                    observation.callerRootParameterIndexValid = true;
                                    observation.callerRootAbiLocation =
                                        root->second.abiLocation;
                                    observation.callerRootBias = 0;
                                    observation.callerRootBiasValid = true;
                                    observation.callVA = instruction.address;
                                    observation.callVAValid = true;
                                    observation.calleeFunctionVA = directTarget;
                                    observation.calleeFunctionVAValid = true;
                                    observation.calleeFormalParameterIndex =
                                        argumentIndex;
                                    observation.calleeFormalParameterIndexValid = true;
                                    observation.calleeAbiLocation = argumentRegister;
                                    observation.directCallTargetExact = true;
                                    observation.argumentRootExact = true;
                                    observation.confidence = 0.99f;
                                    observation.evidence =
                                        "decoder-proved direct internal call passes caller formal parameter " +
                                        std::to_string(root->second.parameter + 1) + " (" +
                                        root->second.abiLocation + ") unchanged in " +
                                        argumentRegister + " to callee formal parameter " +
                                        std::to_string(argumentIndex + 1);
                                    out.directCallFormalBindings.push_back(
                                        std::move(observation));
                                }
                            }
                        }
                    }
                    if (fieldCollectionComplete &&
                        instruction.mnemonic != "lea") {
                        if (!instruction.typedOperands.empty()) {
                            for (size_t operandIndex = 0;
                                 operandIndex < instruction.typedOperands.size(); ++operandIndex) {
                                const TypedOperand& operand =
                                    instruction.typedOperands[operandIndex];
                                if (operand.kind != OperandKind::Memory ||
                                    operand.access == OperandAccess::None || operand.pcRelative ||
                                    !canonReg(operand.indexRegister).empty() ||
                                    !operand.segmentRegister.empty())
                                    continue;
                                const std::string base = canonReg(operand.baseRegister);
                                const auto root = state.find(base);
                                if (root == state.end()) continue;
                                const int64_t localDisplacement = operand.displacementValid
                                                               ? operand.displacement : 0;
                                int64_t displacement = 0;
                                if (!checkedAddSigned(root->second.bias,
                                                      localDisplacement, displacement))
                                    continue;
                                if (out.fieldAccesses.size() >=
                                    kMaxFieldAccessObservations) {
                                    fieldCollectionComplete = false;
                                    fieldCollectionIncompleteReason =
                                        "field-access observation cap reached";
                                    break;
                                }
                                ObjectFieldAccessObservation observation;
                                observation.functionVA = g.funcStart;
                                observation.functionVAValid = true;
                                observation.instructionVA = instruction.address;
                                observation.instructionVAValid = true;
                                observation.operandIndex =
                                    static_cast<uint32_t>(operandIndex);
                                observation.operandIndexValid = true;
                                observation.rootParameterIndex = root->second.parameter;
                                observation.rootParameterIndexValid = true;
                                observation.rootAbiLocation = root->second.abiLocation;
                                observation.displacement = displacement;
                                observation.displacementValid = true;
                                observation.widthBits = operand.widthBits;
                                observation.widthKnown = operand.widthBits != 0;
                                observation.access = accessKind(OperandReads(operand.access),
                                                                OperandWrites(operand.access));
                                observation.exact = true;
                                observation.confidence = 0.98f;
                                observation.evidence =
                                    "typed memory operand " +
                                    std::to_string(operandIndex) + " of `" +
                                    InstructionText(instruction) + "` is rooted in formal parameter " +
                                    std::to_string(root->second.parameter + 1) + " (" +
                                    root->second.abiLocation + ") through CFG-stable register aliases";
                                out.fieldAccesses.push_back(std::move(observation));
                            }
                        } else {
                            // Text-only fixtures retain the same root identity,
                            // but production facts always use typed operands.
                            const std::vector<std::string> operands =
                                splitOps(instruction.operands);
                            for (size_t operandIndex = 0;
                                 operandIndex < operands.size(); ++operandIndex) {
                                const MemOp memory = parseMem(operands[operandIndex]);
                                if (!memory.ok || memory.base.empty() || !memory.index.empty())
                                    continue;
                                const auto root = state.find(memory.base);
                                if (root == state.end()) continue;
                                int64_t displacement = 0;
                                if (!checkedAddSigned(root->second.bias,
                                                     memory.hasDisp ? memory.disp : 0,
                                                     displacement))
                                    continue;
                                if (out.fieldAccesses.size() >=
                                    kMaxFieldAccessObservations) {
                                    fieldCollectionComplete = false;
                                    fieldCollectionIncompleteReason =
                                        "field-access observation cap reached";
                                    break;
                                }
                                bool reads = true;
                                bool writes = false;
                                if (operandIndex == 0 && writesMemFirstOp(instruction)) {
                                    writes = true;
                                    reads = isRmwFirstOp(instruction.mnemonic) ||
                                            instruction.mnemonic == "xchg";
                                }
                                ObjectFieldAccessObservation observation;
                                observation.functionVA = g.funcStart;
                                observation.functionVAValid = true;
                                observation.instructionVA = instruction.address;
                                observation.instructionVAValid = true;
                                observation.operandIndex =
                                    static_cast<uint32_t>(operandIndex);
                                observation.operandIndexValid = true;
                                observation.rootParameterIndex = root->second.parameter;
                                observation.rootParameterIndexValid = true;
                                observation.rootAbiLocation = root->second.abiLocation;
                                observation.displacement = displacement;
                                observation.displacementValid = true;
                                observation.widthBits =
                                    textMemoryWidthBits(operands[operandIndex]);
                                observation.widthKnown = observation.widthBits != 0;
                                observation.access = accessKind(reads, writes);
                                observation.exact = true;
                                observation.confidence = 0.75f;
                                observation.evidence =
                                    "formatted-operand compatibility parse of `" +
                                    InstructionText(instruction) + "` is rooted in formal parameter " +
                                    std::to_string(root->second.parameter + 1) + " (" +
                                    root->second.abiLocation + "); production decoders use typed operands";
                                out.fieldAccesses.push_back(std::move(observation));
                            }
                        }
                    }
                    transferFormal(state, instruction);
                }
            }
            std::sort(out.fieldAccesses.begin(), out.fieldAccesses.end(),
                      [](const ObjectFieldAccessObservation& left,
                         const ObjectFieldAccessObservation& right) {
                          if (left.instructionVA != right.instructionVA)
                              return left.instructionVA < right.instructionVA;
                          return left.operandIndex < right.operandIndex;
                      });
            std::sort(out.directCallFormalBindings.begin(),
                      out.directCallFormalBindings.end(),
                      [](const DirectCallFormalBindingObservation& left,
                         const DirectCallFormalBindingObservation& right) {
                          if (left.callVA != right.callVA)
                              return left.callVA < right.callVA;
                          if (left.calleeFunctionVA != right.calleeFunctionVA)
                              return left.calleeFunctionVA < right.calleeFunctionVA;
                          if (left.calleeFormalParameterIndex !=
                              right.calleeFormalParameterIndex)
                              return left.calleeFormalParameterIndex <
                                     right.calleeFormalParameterIndex;
                          return left.callerRootParameterIndex <
                                 right.callerRootParameterIndex;
                      });
        }
        out.fieldAccessesComplete = fieldCollectionComplete;
        out.fieldAccessIncompleteReason = fieldCollectionComplete
            ? std::string() : fieldCollectionIncompleteReason;
        out.directCallFormalBindingsComplete = bindingCollectionComplete;
        out.directCallFormalBindingIncompleteReason = bindingCollectionComplete
            ? std::string() : bindingCollectionIncompleteReason;

        enum class ReturnAtomKind : uint8_t { Constant, Condition, Field, Call };
        struct ReturnAtom {
            ReturnAtomKind kind = ReturnAtomKind::Constant;
            uint64_t value = 0;
            uint16_t validWidthBits = 0;
            uint32_t fieldIndex = 0;
            uint64_t callVA = 0;
            uint64_t targetVA = 0;
            std::string callName;
            uint64_t producerVA = 0;
            bool exact = false;
        };
        auto sameAtom = [](const ReturnAtom& left, const ReturnAtom& right) {
            return left.kind == right.kind && left.value == right.value &&
                   left.validWidthBits == right.validWidthBits &&
                   left.fieldIndex == right.fieldIndex && left.callVA == right.callVA &&
                   left.targetVA == right.targetVA && left.callName == right.callName &&
                   left.producerVA == right.producerVA && left.exact == right.exact;
        };
        using ReturnValues = std::vector<ReturnAtom>;
        using ReturnState = std::map<std::string, ReturnValues>;
        std::map<std::pair<uint64_t, uint32_t>, uint32_t> fieldByOperand;
        for (uint32_t index = 0; index < out.fieldAccesses.size(); ++index) {
            const ObjectFieldAccessObservation& field = out.fieldAccesses[index];
            fieldByOperand.emplace(std::make_pair(field.instructionVA,
                                                  field.operandIndex), index);
        }

        auto assignAtom = [](ReturnState& state, const std::string& destination,
                             ReturnAtom atom) {
            if (destination.empty()) return;
            state[destination] = ReturnValues{std::move(atom)};
        };
        auto transferReturn = [&](ReturnState& state, const Instruction& instruction) {
            if (InstructionIsCall(instruction)) {
                static const char* kVolatile[] = {
                    "rax", "rcx", "rdx", "r8", "r9", "r10", "r11"
                };
                for (const char* reg : kVolatile) state.erase(reg);
                uint64_t target = 0;
                if (TryGetDirectTarget(instruction, target)) {
                    const std::string resolved = callName(instruction);
                    if (!resolved.empty()) {
                        ReturnAtom atom;
                        atom.kind = ReturnAtomKind::Call;
                        atom.validWidthBits = x64 ? 64 : 32;
                        atom.callVA = instruction.address;
                        atom.targetVA = target;
                        atom.callName = resolved;
                        atom.producerVA = instruction.address;
                        atom.exact = true;
                        assignAtom(state, "rax", std::move(atom));
                    }
                }
                return;
            }

            const RW effects = classifyRW(instruction);
            std::string definedRegister;
            std::string definedSpelling;
            bool definitionModelled = false;

            if (effects.zeroIdiom && !effects.writes.empty()) {
                definedRegister = effects.writes.front();
                if (!instruction.typedOperands.empty() &&
                    instruction.typedOperands[0].kind == OperandKind::Register)
                    definedSpelling = instruction.typedOperands[0].registerName;
                else {
                    const std::vector<std::string> operands = splitOps(instruction.operands);
                    if (!operands.empty()) definedSpelling = operands[0];
                }
                ReturnAtom atom;
                atom.kind = ReturnAtomKind::Constant;
                atom.value = 0;
                atom.validWidthBits = registerWidthBits(definedSpelling, x64);
                if (!instruction.typedOperands.empty() &&
                    instruction.typedOperands[0].widthBits)
                    atom.validWidthBits = instruction.typedOperands[0].widthBits;
                atom.producerVA = instruction.address;
                atom.exact = atom.validWidthBits != 0;
                assignAtom(state, definedRegister, std::move(atom));
                definitionModelled = true;
            } else if (instruction.mnemonic.rfind("set", 0) == 0) {
                if (!instruction.typedOperands.empty() &&
                    instruction.typedOperands[0].kind == OperandKind::Register &&
                    OperandWrites(instruction.typedOperands[0].access)) {
                    definedSpelling = instruction.typedOperands[0].registerName;
                    definedRegister = canonReg(definedSpelling);
                    const uint16_t width = instruction.typedOperands[0].widthBits
                                         ? instruction.typedOperands[0].widthBits
                                         : registerWidthBits(definedSpelling, x64);
                    if (!definedRegister.empty() && width == 8 &&
                        !isHighByteRegister(definedSpelling)) {
                        ReturnAtom atom;
                        atom.kind = ReturnAtomKind::Condition;
                        atom.validWidthBits = 8;
                        atom.producerVA = instruction.address;
                        atom.exact = true;
                        assignAtom(state, definedRegister, std::move(atom));
                        definitionModelled = true;
                    }
                } else if (instruction.typedOperands.empty()) {
                    const std::vector<std::string> operands = splitOps(instruction.operands);
                    if (!operands.empty()) {
                        definedSpelling = operands[0];
                        definedRegister = canonReg(definedSpelling);
                        if (!definedRegister.empty() &&
                            registerWidthBits(definedSpelling, x64) == 8 &&
                            !isHighByteRegister(definedSpelling)) {
                            ReturnAtom atom;
                            atom.kind = ReturnAtomKind::Condition;
                            atom.validWidthBits = 8;
                            atom.producerVA = instruction.address;
                            atom.exact = true;
                            assignAtom(state, definedRegister, std::move(atom));
                            definitionModelled = true;
                        }
                    }
                }
            } else if (instruction.mnemonic == "mov" ||
                       instruction.mnemonic == "movzx") {
                if (!instruction.typedOperands.empty() &&
                    instruction.typedOperands.size() >= 2 &&
                    instruction.typedOperands[0].kind == OperandKind::Register &&
                    OperandWrites(instruction.typedOperands[0].access)) {
                    const TypedOperand& destination = instruction.typedOperands[0];
                    const TypedOperand& source = instruction.typedOperands[1];
                    definedSpelling = destination.registerName;
                    definedRegister = canonReg(definedSpelling);
                    const uint16_t destinationWidth = destination.widthBits
                        ? destination.widthBits
                        : registerWidthBits(definedSpelling, x64);
                    if (!definedRegister.empty() && source.kind == OperandKind::Immediate) {
                        ReturnAtom atom;
                        atom.kind = ReturnAtomKind::Constant;
                        atom.value = source.immediate;
                        atom.validWidthBits = destinationWidth;
                        atom.producerVA = instruction.address;
                        atom.exact = destinationWidth != 0;
                        assignAtom(state, definedRegister, std::move(atom));
                        definitionModelled = true;
                    } else if (!definedRegister.empty() &&
                               source.kind == OperandKind::Register) {
                        const std::string sourceRegister = canonReg(source.registerName);
                        const auto found = state.find(sourceRegister);
                        if (found != state.end()) state[definedRegister] = found->second;
                        else state.erase(definedRegister);
                        definitionModelled = true;
                    } else if (!definedRegister.empty() &&
                               source.kind == OperandKind::Memory &&
                               OperandReads(source.access)) {
                        const auto field = fieldByOperand.find(
                            std::make_pair(instruction.address, 1u));
                        if (field != fieldByOperand.end()) {
                            const ObjectFieldAccessObservation& access =
                                out.fieldAccesses[field->second];
                            if (access.widthKnown && access.widthBits <= 8 &&
                                (instruction.mnemonic == "movzx" ||
                                 destinationWidth == 8)) {
                                ReturnAtom atom;
                                atom.kind = ReturnAtomKind::Field;
                                atom.validWidthBits = access.widthBits;
                                atom.fieldIndex = field->second;
                                atom.producerVA = instruction.address;
                                atom.exact = access.exact;
                                assignAtom(state, definedRegister, std::move(atom));
                                definitionModelled = true;
                            }
                        }
                    }
                } else if (instruction.typedOperands.empty()) {
                    const std::vector<std::string> operands = splitOps(instruction.operands);
                    if (operands.size() >= 2) {
                        definedSpelling = operands[0];
                        definedRegister = canonReg(definedSpelling);
                        const uint16_t destinationWidth =
                            registerWidthBits(definedSpelling, x64);
                        int64_t immediate = 0;
                        const std::string sourceRegister = canonReg(operands[1]);
                        if (!definedRegister.empty() && parseImm(operands[1], immediate)) {
                            ReturnAtom atom;
                            atom.kind = ReturnAtomKind::Constant;
                            atom.value = static_cast<uint64_t>(immediate);
                            atom.validWidthBits = destinationWidth;
                            atom.producerVA = instruction.address;
                            atom.exact = destinationWidth != 0;
                            assignAtom(state, definedRegister, std::move(atom));
                            definitionModelled = true;
                        } else if (!definedRegister.empty() && !sourceRegister.empty()) {
                            const auto found = state.find(sourceRegister);
                            if (found != state.end()) state[definedRegister] = found->second;
                            else state.erase(definedRegister);
                            definitionModelled = true;
                        } else if (!definedRegister.empty() &&
                                   operands[1].find('[') != std::string::npos) {
                            const auto field = fieldByOperand.find(
                                std::make_pair(instruction.address, 1u));
                            if (field != fieldByOperand.end()) {
                                const ObjectFieldAccessObservation& access =
                                    out.fieldAccesses[field->second];
                                if (access.widthKnown && access.widthBits <= 8 &&
                                    (instruction.mnemonic == "movzx" ||
                                     destinationWidth == 8)) {
                                    ReturnAtom atom;
                                    atom.kind = ReturnAtomKind::Field;
                                    atom.validWidthBits = access.widthBits;
                                    atom.fieldIndex = field->second;
                                    atom.producerVA = instruction.address;
                                    atom.exact = access.exact;
                                    assignAtom(state, definedRegister, std::move(atom));
                                    definitionModelled = true;
                                }
                            }
                        }
                    }
                }
            }

            for (const std::string& written : effects.writes) {
                if (!definitionModelled || written != definedRegister)
                    state.erase(written);
            }
        };

        constexpr size_t kMaxReturnValuesPerRegister = 8;
        bool returnDataFlowComplete = true;
        auto mergeReturnState = [&](ReturnState& destination,
                                    const ReturnState& incoming) {
            bool changed = false;
            for (auto current = destination.begin(); current != destination.end();) {
                const auto other = incoming.find(current->first);
                if (other == incoming.end()) {
                    current = destination.erase(current);
                    changed = true;
                    continue;
                }
                bool exceededValueCap = false;
                for (const ReturnAtom& atom : other->second) {
                    const bool present = std::any_of(
                        current->second.begin(), current->second.end(),
                        [&](const ReturnAtom& existing) {
                            return sameAtom(existing, atom);
                        });
                    if (present) continue;
                    if (current->second.size() >= kMaxReturnValuesPerRegister) {
                        returnDataFlowComplete = false;
                        exceededValueCap = true;
                        break;
                    }
                    current->second.push_back(atom);
                    changed = true;
                }
                if (exceededValueCap) {
                    current = destination.erase(current);
                    changed = true;
                    continue;
                }
                ++current;
            }
            return changed;
        };

        std::vector<ReturnState> returnIn(g.blocks.size());
        std::vector<bool> returnReached(g.blocks.size(), false);
        returnReached[entryBlock] = true;
        std::deque<BlockIndex> returnWork{entryBlock};
        size_t returnSteps = 0;
        while (!returnWork.empty() && returnSteps++ < dataFlowBudget) {
            const BlockIndex blockIndex = returnWork.front();
            returnWork.pop_front();
            ReturnState outgoing = returnIn[blockIndex];
            for (const Instruction& instruction : g.blocks[blockIndex].insns)
                transferReturn(outgoing, instruction);
            for (BlockIndex successor : g.blocks[blockIndex].succ) {
                if (successor >= g.blocks.size()) {
                    returnDataFlowComplete = false;
                    continue;
                }
                bool changed = false;
                if (!returnReached[successor]) {
                    returnReached[successor] = true;
                    returnIn[successor] = outgoing;
                    changed = true;
                } else {
                    changed = mergeReturnState(returnIn[successor], outgoing);
                }
                if (changed) returnWork.push_back(successor);
            }
        }
        if (!returnWork.empty()) returnDataFlowComplete = false;

        auto classifyExit = [&](uint64_t returnVA,
                                const ReturnValues* values) {
            FunctionReturnExitObservation exit;
            exit.returnVA = returnVA;
            exit.returnVAValid = true;
            if (!values || values->empty()) {
                exit.evidence =
                    "ABI return register has no single proved producer on every path to this return";
                return exit;
            }

            bool everyConstantBoolean = true;
            bool everyCondition = true;
            bool everyBooleanProducer = true;
            bool everyField = true;
            bool everyCall = true;
            bool everyExact = true;
            uint16_t minimumWidth = (std::numeric_limits<uint16_t>::max)();
            for (const ReturnAtom& atom : *values) {
                everyConstantBoolean &= atom.kind == ReturnAtomKind::Constant &&
                                        atom.value <= 1;
                everyCondition &= atom.kind == ReturnAtomKind::Condition;
                everyBooleanProducer &=
                    (atom.kind == ReturnAtomKind::Constant && atom.value <= 1) ||
                    atom.kind == ReturnAtomKind::Condition;
                everyField &= atom.kind == ReturnAtomKind::Field;
                everyCall &= atom.kind == ReturnAtomKind::Call;
                everyExact &= atom.exact;
                if (!atom.validWidthBits) minimumWidth = 0;
                else if (minimumWidth) minimumWidth =
                    (std::min)(minimumWidth, atom.validWidthBits);
            }
            if (minimumWidth == (std::numeric_limits<uint16_t>::max)())
                minimumWidth = 0;
            exit.validWidthBits = minimumWidth;
            exit.validWidthKnown = minimumWidth != 0;
            exit.exact = everyExact;

            if (everyConstantBoolean ||
                (everyBooleanProducer && !everyCondition)) {
                exit.kind = FunctionReturnKind::CanonicalBoolean;
                const uint64_t first = values->front().value;
                const bool sameConstant = everyConstantBoolean &&
                    std::all_of(values->begin(), values->end(),
                                [&](const ReturnAtom& atom) {
                                    return atom.value == first;
                                });
                if (sameConstant) {
                    exit.constantValue = first;
                    exit.constantValueValid = true;
                }
                exit.confidence = everyExact ? 0.98f : 0.8f;
                exit.evidence =
                    "every value reaching the ABI return register is proved to be 0 or 1";
            } else if (everyCondition && exit.validWidthKnown) {
                exit.kind = FunctionReturnKind::MaterializedCondition;
                exit.confidence = everyExact ? 0.96f : 0.8f;
                exit.evidence =
                    "every value reaching the ABI return register is materialized by SETcc";
            } else if (everyField) {
                const uint32_t fieldIndex = values->front().fieldIndex;
                const bool sameField = std::all_of(
                    values->begin(), values->end(),
                    [&](const ReturnAtom& atom) {
                        return atom.fieldIndex == fieldIndex;
                    });
                if (sameField && fieldIndex < out.fieldAccesses.size()) {
                    const ObjectFieldAccessObservation& field =
                        out.fieldAccesses[fieldIndex];
                    if (field.widthKnown && field.widthBits <= 8 && field.exact) {
                        const uint64_t displacementMagnitude = field.displacement < 0
                            ? static_cast<uint64_t>(-(field.displacement + 1)) + 1
                            : static_cast<uint64_t>(field.displacement);
                        exit.kind = FunctionReturnKind::FieldBackedBoolean;
                        exit.fieldAccessIndex = fieldIndex;
                        exit.fieldAccessIndexValid = true;
                        exit.confidence = 0.92f;
                        exit.evidence =
                            "ABI return value is the exact byte/bool read from formal parameter " +
                            std::to_string(field.rootParameterIndex + 1) + " at displacement " +
                            (field.displacement < 0 ? "-" : "+") +
                            vaHex(displacementMagnitude);
                    }
                }
            } else if (everyCall) {
                const ReturnAtom& first = values->front();
                const bool sameCall = std::all_of(
                    values->begin(), values->end(),
                    [&](const ReturnAtom& atom) {
                        return atom.callVA == first.callVA &&
                               atom.targetVA == first.targetVA &&
                               atom.callName == first.callName;
                    });
                if (sameCall && !first.callName.empty()) {
                    exit.kind = FunctionReturnKind::ForwardedCall;
                    exit.forwardedCallVA = first.callVA;
                    exit.forwardedCallVAValid = true;
                    exit.forwardedTargetVA = first.targetVA;
                    exit.forwardedTargetVAValid = true;
                    exit.forwardedName = first.callName;
                    exit.confidence = 0.9f;
                    exit.evidence = "named direct call `" + first.callName +
                                    "` remains in the ABI return register until ret";
                }
            }
            if (exit.kind == FunctionReturnKind::Unknown) {
                const bool nonBooleanConstant = std::any_of(
                    values->begin(), values->end(), [](const ReturnAtom& atom) {
                        return atom.kind == ReturnAtomKind::Constant && atom.value > 1;
                    });
                exit.evidence = nonBooleanConstant
                    ? "a reachable return value is a constant other than canonical boolean 0/1"
                    : "reachable return sources are not one conservative supported class";
            }
            return exit;
        };

        for (int orderedBlock : order) {
            const BlockIndex blockIndex = static_cast<BlockIndex>(orderedBlock);
            if (!returnReached[blockIndex]) continue;
            ReturnState state = returnIn[blockIndex];
            for (const Instruction& instruction : g.blocks[blockIndex].insns) {
                if (InstructionIsReturn(instruction)) {
                    const auto result = state.find("rax");
                    out.returnObservation.exits.push_back(classifyExit(
                        instruction.address,
                        result == state.end() ? nullptr : &result->second));
                }
                transferReturn(state, instruction);
            }
        }
        std::sort(out.returnObservation.exits.begin(),
                  out.returnObservation.exits.end(),
                  [](const FunctionReturnExitObservation& left,
                     const FunctionReturnExitObservation& right) {
                      return left.returnVA < right.returnVA;
                  });

        auto appendReturnReason = [&](const std::string& reason) {
            if (reason.empty()) return;
            if (!out.returnObservation.incompleteReason.empty())
                out.returnObservation.incompleteReason += "; ";
            out.returnObservation.incompleteReason += reason;
        };
        bool returnComplete = true;
        if (!g.complete) {
            returnComplete = false;
            appendReturnReason(g.incompleteReason.empty()
                ? "CFG is incomplete"
                : "CFG is incomplete: " + g.incompleteReason);
        }
        if (!entryExact) {
            returnComplete = false;
            appendReturnReason("CFG has no block at the declared function entry");
        }
        if (!returnDataFlowComplete) {
            returnComplete = false;
            appendReturnReason("return-value data flow exceeded its bounded state or step limit");
        }
        if (out.returnObservation.exits.empty()) {
            returnComplete = false;
            appendReturnReason("no reachable machine return was decoded");
        }
        for (const FunctionReturnExitObservation& exit : out.returnObservation.exits) {
            if (exit.kind == FunctionReturnKind::Unknown) {
                returnComplete = false;
                appendReturnReason("return at " + vaHex(exit.returnVA) +
                                   " has an unknown value");
            }
        }

        FunctionReturnKind aggregate = FunctionReturnKind::Unknown;
        if (returnComplete) {
            const FunctionReturnKind first = out.returnObservation.exits.front().kind;
            const bool sameKind = std::all_of(
                out.returnObservation.exits.begin(), out.returnObservation.exits.end(),
                [&](const FunctionReturnExitObservation& exit) {
                    return exit.kind == first;
                });
            const bool allBoolean = std::all_of(
                out.returnObservation.exits.begin(), out.returnObservation.exits.end(),
                [](const FunctionReturnExitObservation& exit) {
                    return exit.kind == FunctionReturnKind::CanonicalBoolean ||
                           exit.kind == FunctionReturnKind::MaterializedCondition;
                });
            if (allBoolean && !sameKind) {
                aggregate = FunctionReturnKind::CanonicalBoolean;
            } else if (sameKind && first == FunctionReturnKind::FieldBackedBoolean) {
                const ObjectFieldAccessObservation& firstField = out.fieldAccesses[
                    out.returnObservation.exits.front().fieldAccessIndex];
                const bool sameIdentity = std::all_of(
                    out.returnObservation.exits.begin(), out.returnObservation.exits.end(),
                    [&](const FunctionReturnExitObservation& exit) {
                        if (!exit.fieldAccessIndexValid ||
                            exit.fieldAccessIndex >= out.fieldAccesses.size())
                            return false;
                        const ObjectFieldAccessObservation& field =
                            out.fieldAccesses[exit.fieldAccessIndex];
                        return field.functionVA == firstField.functionVA &&
                               field.rootParameterIndex == firstField.rootParameterIndex &&
                               field.displacement == firstField.displacement &&
                               field.widthKnown == firstField.widthKnown &&
                               field.widthBits == firstField.widthBits;
                    });
                if (sameIdentity) aggregate = first;
            } else if (sameKind && first == FunctionReturnKind::ForwardedCall) {
                const FunctionReturnExitObservation& firstExit =
                    out.returnObservation.exits.front();
                const bool sameTarget = std::all_of(
                    out.returnObservation.exits.begin(), out.returnObservation.exits.end(),
                    [&](const FunctionReturnExitObservation& exit) {
                        return exit.forwardedTargetVAValid &&
                               exit.forwardedTargetVA == firstExit.forwardedTargetVA &&
                               exit.forwardedName == firstExit.forwardedName;
                    });
                if (sameTarget) aggregate = first;
            } else if (sameKind) {
                aggregate = first;
            }
            if (aggregate == FunctionReturnKind::Unknown) {
                returnComplete = false;
                appendReturnReason("reachable returns have heterogeneous source identities");
            }
        }

        out.returnObservation.complete = returnComplete;
        out.returnObservation.kind = returnComplete
            ? aggregate : FunctionReturnKind::Unknown;
        if (returnComplete) {
            uint16_t minimumWidth = (std::numeric_limits<uint16_t>::max)();
            float minimumConfidence = 1.0f;
            for (const FunctionReturnExitObservation& exit :
                 out.returnObservation.exits) {
                if (!exit.validWidthKnown) minimumWidth = 0;
                else if (minimumWidth) minimumWidth =
                    (std::min)(minimumWidth, exit.validWidthBits);
                minimumConfidence = (std::min)(minimumConfidence, exit.confidence);
            }
            if (minimumWidth == (std::numeric_limits<uint16_t>::max)())
                minimumWidth = 0;
            out.returnObservation.validWidthBits = minimumWidth;
            out.returnObservation.validWidthKnown = minimumWidth != 0;
            out.returnObservation.confidence = minimumConfidence;
            out.returnObservation.evidence =
                std::to_string(out.returnObservation.exits.size()) +
                " reachable return exit(s) agree on " +
                FunctionReturnKindName(out.returnObservation.kind);
        }
    }

    // ---- 10) Summary + ordering -----------------------------------------------
    {
        std::sort(out.notes.begin(), out.notes.end(),
                  [](const FnNote& a, const FnNote& b) {
                      if (a.sourceValid != b.sourceValid) return !a.sourceValid;
                      if (a.va != b.va) return a.va < b.va;
                      return (int)a.kind < (int)b.kind;
                  });
        int nLocals = 0, nArgsStack = 0, nCalls = 0, nPatterns = 0;
        for (const StackSlot& s : out.stack) (s.isArg ? nArgsStack : nLocals)++;
        for (const FnNote& n : out.notes) {
            if (n.kind == NoteKind::Call || n.kind == NoteKind::IndirectCall || n.kind == NoteKind::VirtualCall) ++nCalls;
            if (n.kind == NoteKind::Pattern) ++nPatterns;
        }
        std::string s = out.convention.empty() ? "" : out.convention;
        size_t paren = s.find(" (assumed");
        if (paren != std::string::npos) s = s.substr(0, paren) + "?";
        if (!out.args.empty()) s += (s.empty() ? "" : " · ") + std::to_string(out.args.size()) + " arg(s)";
        if (out.frameBytes)   s += (s.empty() ? "" : " · ") + ("frame " + vaHex(out.frameBytes));
        if (nLocals)          s += (s.empty() ? "" : " · ") + std::to_string(nLocals) + " local(s)";
        if (!loops.empty())   s += (s.empty() ? "" : " · ") + std::to_string(loops.size()) + " loop(s)";
        for (const FnNote& n : out.notes)
            if (n.kind == NoteKind::Pattern && !n.sourceValid && s.size() < 140) {
                s += " · " + n.text;
                break;
            }
        const std::string metadata = metadataSummary();
        out.summary = s.empty() ? metadata : s + " · " + metadata;
    }
    return out;
}

} // namespace ds
