// CodeExport.cpp -- see CodeExport.h.
#include "CodeExport.h"

#include "BinaryFile.h"
#include "ApiDatabase.h"
#include "Demangle.h"
#include "../Disasm/JvmDisassembler.h"
#include "../Disasm/GmlDisassembler.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <unordered_set>

namespace ds {
namespace {

namespace fs = std::filesystem;

NoreturnCallResolver ExportNoreturnResolver(const CodeExportRequest& req) {
    auto proven = std::make_shared<std::vector<uint64_t>>();
    auto forcedReturning = std::make_shared<std::vector<uint64_t>>();
    for (const CodeExportFunction& function : req.functions) {
        if (!function.noreturnValid) continue;
        (function.noreturn ? *proven : *forcedReturning).push_back(function.address);
    }
    if (req.binary) {
        for (const BinaryFile::Import& item : req.binary->imports())
            if (item.addressKnown && IsKnownNoreturnApi(item.name))
                proven->push_back(item.iatVA);
    }
    auto normalize = [](std::vector<uint64_t>& values) {
        std::sort(values.begin(), values.end());
        values.erase(std::unique(values.begin(), values.end()), values.end());
    };
    normalize(*proven);
    normalize(*forcedReturning);
    if (proven->empty()) return {};
    return [proven = std::move(proven), forcedReturning = std::move(forcedReturning)](
               uint64_t target) {
        return !std::binary_search(forcedReturning->begin(), forcedReturning->end(), target) &&
               std::binary_search(proven->begin(), proven->end(), target);
    };
}

fs::path PathFromUtf8(const std::string& path) {
    std::u8string u8(path.size(), u8'\0');
    if (!path.empty()) std::memcpy(u8.data(), path.data(), path.size());
    return fs::path(u8);
}

std::string Hex(uint64_t v, unsigned width = 0) {
    char b[40];
    if (width) std::snprintf(b, sizeof(b), "%0*llX", (int)width, (unsigned long long)v);
    else       std::snprintf(b, sizeof(b), "%llX", (unsigned long long)v);
    return b;
}

std::string Trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string OneLine(std::string s) {
    for (char& c : s) if (c == '\r' || c == '\n') c = ' ';
    return s;
}

std::string BlockComment(std::string s) {
    s = OneLine(std::move(s));
    for (size_t p = s.find("*/"); p != std::string::npos; p = s.find("*/", p + 3))
        s.replace(p, 2, "* /");
    return s;
}

std::string EscapeCString(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '\\': o += "\\\\"; break;
            case '"':  o += "\\\""; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c >= 0x20 && c < 0x7f) o += (char)c;
                else { char b[5]; std::snprintf(b, sizeof(b), "\\x%02X", c); o += b; }
                break;
        }
    }
    return o;
}

bool IsIdentStart(char c) {
    return std::isalpha((unsigned char)c) != 0 || c == '_';
}
bool IsIdentChar(char c) {
    return std::isalnum((unsigned char)c) != 0 || c == '_';
}

const std::unordered_set<std::string>& CKeywords() {
    static const std::unordered_set<std::string> k = {
        "auto","break","case","char","const","continue","default","do","double","else",
        "enum","extern","float","for","goto","if","inline","int","long","register",
        "restrict","return","short","signed","sizeof","static","struct","switch","typedef",
        "union","unsigned","void","volatile","while","_Alignas","_Alignof","_Atomic","_Bool",
        "_Complex","_Generic","_Imaginary","_Noreturn","_Static_assert","_Thread_local"
    };
    return k;
}

std::string SanitizeIdentifier(const std::string& original, uint64_t fallbackVA) {
    std::string s;
    s.reserve(original.size() + 8);
    for (unsigned char c : original) s += (std::isalnum(c) || c == '_') ? (char)c : '_';
    while (!s.empty() && s.back() == '_') s.pop_back();
    if (s.empty()) s = "sub_" + Hex(fallbackVA);
    if (!IsIdentStart(s.front())) s = "sym_" + s;
    // Avoid implementation-reserved identifiers as well as language keywords.
    if (CKeywords().count(s) || s.rfind("__", 0) == 0 ||
        (s.size() > 1 && s[0] == '_' && std::isupper((unsigned char)s[1])))
        s = "ds_" + s;
    return s;
}

struct Writer {
    std::ostream& out;
    uint64_t bytes = 0;
    bool ok = true;

    void put(const std::string& s) {
        if (!ok) return;
        out.write(s.data(), (std::streamsize)s.size());
        ok = (bool)out;
        if (ok) bytes += (uint64_t)s.size();
    }
    void line(const std::string& s = {}) { put(s); put("\n"); }
};

void Publish(const CodeExportProgressFn& fn, CodeExportPhase phase,
             uint64_t current, uint64_t total, uint64_t functionVA, uint64_t bytes) {
    if (!fn) return;
    CodeExportProgress p;
    p.phase = phase; p.current = current; p.total = total;
    p.functionVA = functionVA; p.bytesWritten = bytes;
    fn(p);
}

CodeExportResult Failure(const CodeExportRequest& req, const std::string& message,
                         uint64_t bytes = 0, bool cancelled = false) {
    CodeExportResult r;
    r.path = req.outputPath; r.message = message; r.bytesWritten = bytes;
    r.cancelled = cancelled;
    return r;
}

std::vector<CodeExportFunction> SortedFunctions(const CodeExportRequest& req) {
    std::vector<CodeExportFunction> f = req.functions;
    std::stable_sort(f.begin(), f.end(), [](const auto& a, const auto& b) {
        return a.address < b.address;
    });
    f.erase(std::unique(f.begin(), f.end(), [](const auto& a, const auto& b) {
        return a.address == b.address;
    }), f.end());
    return f;
}

std::vector<CodeExportFunction> SelectedFunctions(
    const CodeExportRequest& req, const std::vector<CodeExportFunction>& sorted) {
    std::vector<CodeExportFunction> f = sorted;
    if (req.scope == CodeExportScope::Function) {
        f.erase(std::remove_if(f.begin(), f.end(), [&](const auto& x) {
            return x.address != req.functionVA;
        }), f.end());
    }
    return f;
}

DecompileNameMap CompleteNames(const CodeExportRequest& req) {
    DecompileNameMap names;
    if (req.binary) {
        for (const auto& im : req.binary->imports())
            if (im.addressKnown && !im.name.empty())
                names[im.iatVA] = im.dll + "." + DemangleForLabel(im.name);
    }
    for (const auto& f : req.functions) if (!f.name.empty()) names[f.address] = f.name;
    for (const auto& n : req.names) if (!n.second.empty()) names[n.first] = n.second;
    return names;
}

std::string FunctionDiscoveryMetadata(const CodeExportFunction& function) {
    std::string text = "seed=" + std::string(FunctionSeedKindName(function.seedKind)) +
                       "; boundary=" +
                       FunctionBoundaryConfidenceName(function.boundaryConfidence) +
                       "; ownership=" +
                       (function.ownershipTruncated ? "truncated" : "complete") +
                       "; chunks=" + std::to_string(function.chunks.size());
    if (!function.chunks.empty()) {
        text += " [";
        const size_t shown = std::min<size_t>(function.chunks.size(), 8);
        for (size_t i = 0; i < shown; ++i) {
            if (i) text += ", ";
            text += "0x" + Hex(function.chunks[i].address) + "+0x" +
                    Hex(function.chunks[i].size);
        }
        if (shown < function.chunks.size()) text += ", ...";
        text += "]";
    }
    return text;
}

uint64_t FunctionSpan(const BinaryFile& bin, const CodeExportFunction& f,
                      const std::vector<CodeExportFunction>& all) {
    size_t avail = 0;
    if (!bin.ptrFromVA(f.address, avail) || !avail) return 0;
    uint64_t span = f.size ? (uint64_t)f.size : (uint64_t)avail;
    auto it = std::upper_bound(all.begin(), all.end(), f.address,
        [](uint64_t va, const CodeExportFunction& x) { return va < x.address; });
    if (!f.size && it != all.end() && it->address > f.address)
        span = std::min(span, it->address - f.address);
    span = std::min<uint64_t>(span, (uint64_t)avail);
    span = std::min<uint64_t>(span, UINT64_MAX - f.address);
    return span;
}

struct AsmRange {
    uint64_t va = 0;
    uint64_t size = 0;
    std::string name;
};

std::vector<AsmRange> AssemblyRanges(const CodeExportRequest& req,
                                     const std::vector<CodeExportFunction>& selected,
                                     const std::vector<CodeExportFunction>& all) {
    std::vector<AsmRange> ranges;
    if (!req.binary) return ranges;
    if (req.scope == CodeExportScope::Function) {
        if (selected.empty()) return ranges;
        const CodeExportFunction& function = selected.front();
        if (!function.chunks.empty()) {
            for (size_t i = 0; i < function.chunks.size(); ++i) {
                const FunctionChunk& chunk = function.chunks[i];
                size_t available = 0;
                if (!chunk.size || !req.binary->ptrFromVA(chunk.address, available)) continue;
                const uint64_t span = std::min<uint64_t>(chunk.size, available);
                if (!span) continue;
                std::string name = function.name;
                if (function.chunks.size() > 1)
                    name += " chunk " + std::to_string(i + 1) + "/" +
                            std::to_string(function.chunks.size());
                ranges.push_back({chunk.address, span, std::move(name)});
            }
        } else {
            uint64_t span = FunctionSpan(*req.binary, function, all);
            if (span) ranges.push_back({function.address, span, function.name});
        }
        return ranges;
    }
    for (const Section& s : req.binary->sections()) {
        if (!s.executable || !s.rawSize) continue;
        if (s.virtualAddress > UINT64_MAX - req.binary->imageBase()) continue;
        uint64_t va = req.binary->imageBase() + s.virtualAddress;
        size_t avail = 0;
        if (!req.binary->ptrFromVA(va, avail) || !avail) continue;
        uint64_t n = std::min<uint64_t>(s.rawSize, (uint64_t)avail);
        if (n) ranges.push_back({ va, n, s.name });
    }
    std::sort(ranges.begin(), ranges.end(), [](const auto& a, const auto& b) { return a.va < b.va; });
    return ranges;
}

std::string BytesFor(const uint8_t* p, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        char b[4]; std::snprintf(b, sizeof(b), "%02X", p[i]);
        if (i) s += ' ';
        s += b;
    }
    return s;
}

std::string DbOperandsFor(const uint8_t* p, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        char b[8]; std::snprintf(b, sizeof(b), "0x%02X", p[i]);
        if (i) s += ", ";
        s += b;
    }
    return s;
}

CodeExportResult GenerateAssembly(const CodeExportRequest& req, IDisassembler& dis,
                                  Writer& w, const CodeExportCancelFn& cancelled,
                                  const CodeExportProgressFn& progress) {
    const auto all = SortedFunctions(req);
    const auto selected = SelectedFunctions(req, all);
    if (req.scope == CodeExportScope::Function && selected.empty())
        return Failure(req, "The selected function was not present in the export snapshot.");
    const auto ranges = AssemblyRanges(req, selected, all);
    if (ranges.empty()) return Failure(req, "No file-backed executable bytes are available to export.");

    DecompileNameMap names = CompleteNames(req);
    std::map<uint64_t, std::string> labels;
    std::unordered_set<std::string> usedLabels;
    for (const auto& f : all) {
        auto it = names.find(f.address);
        std::string label = SanitizeIdentifier(it == names.end() ? f.name : it->second, f.address);
        if (!usedLabels.insert(label).second) {
            label += "_" + Hex(f.address);
            unsigned suffix = 2;
            while (!usedLabels.insert(label).second) label += "_" + std::to_string(suffix++);
        }
        labels[f.address] = std::move(label);
    }

    uint64_t total = 0;
    for (const auto& r : ranges) total += r.size;
    const unsigned aw = req.binary->is64Bit() ? 16u : 8u;
    w.line("; DisasmStudio assembly export");
    w.line("; Source: " + OneLine(req.sourceName.empty() ? req.binary->path() : req.sourceName));
    w.line("; Architecture: " + std::string(ArchName(req.arch)));
    w.line("; Decoder: " + std::string(dis.engineName()));
    w.line();

    uint64_t done = 0;
    Publish(progress, CodeExportPhase::Assembly, done, total, 0, w.bytes);
    for (const AsmRange& r : ranges) {
        if (cancelled && cancelled())
            return Failure(req, "Export cancelled; the destination was left unchanged.", w.bytes, true);
        w.line("; -----------------------------------------------------------------------------");
        w.line("; " + (r.name.empty() ? std::string("executable range") : r.name) +
               " [0x" + Hex(r.va) + ", 0x" + Hex(r.va + r.size) + ")");
        size_t avail = 0;
        const uint8_t* p = req.binary->ptrFromVA(r.va, avail);
        if (!p) continue;
        size_t off = 0;
        const size_t limit = (size_t)std::min<uint64_t>(r.size, (uint64_t)avail);
        while (off < limit) {
            if ((off & 0x3ffu) == 0) {
                if ((cancelled && cancelled()) ||
                    (req.expectedImageRevision && req.binary->imageRevision() != req.expectedImageRevision))
                    return Failure(req, "Export cancelled because the image changed.", w.bytes, true);
                Publish(progress, CodeExportPhase::Assembly, done + off, total, 0, w.bytes);
            }
            uint64_t va = 0;
            if (!CheckedAddressAdd(r.va, static_cast<uint64_t>(off), va))
                return Failure(req, "Export stopped at an overflowing virtual address.", w.bytes);
            auto lab = labels.find(va);
            if (lab != labels.end()) {
                w.line();
                auto metadata = std::lower_bound(
                    all.begin(), all.end(), va,
                    [](const CodeExportFunction& function, uint64_t address) {
                        return function.address < address;
                    });
                if (metadata != all.end() && metadata->address == va)
                    w.line("    ; Discovery: " + FunctionDiscoveryMetadata(*metadata));
                w.line(lab->second + ":");
            }
            auto uc = req.comments.find(va);
            if (uc != req.comments.end() && !uc->second.empty()) w.line("    ; " + OneLine(uc->second));

            Instruction in;
            if (!dis.decodeOne(p + off, limit - off, va, in) || !in.length || in.length > limit - off) {
                const size_t step = std::min<size_t>(
                    limit - off, std::max<uint32_t>(1, dis.invalidDecodeWidth()));
                w.line("    " + Hex(va, aw) + "  " + BytesFor(p + off, step) +
                       "                    db " + DbOperandsFor(p + off, step) + " ; decode failure");
                off += step;
                continue;
            }
            std::string bytes = in.bytes.empty() ? BytesFor(p + off, in.length) : in.bytes;
            if (bytes.size() < 24) bytes.append(24 - bytes.size(), ' ');
            std::string line = "    " + Hex(va, aw) + "  " + bytes + "  " + InstructionText(in);
            std::string comment = in.comment;
            if (uc != req.comments.end() && !uc->second.empty()) {
                if (!comment.empty()) comment += " | ";
                comment += OneLine(uc->second);
            }
            if (HasBranchTarget(in)) {
                auto targetName = labels.find(in.branchTarget);
                if (targetName != labels.end()) {
                    if (!comment.empty()) comment += " | ";
                    comment += "target " + targetName->second;
                }
            }
            if (!comment.empty()) line += " ; " + OneLine(comment);
            w.line(line);
            off += in.length;
            if (!w.ok) return Failure(req, "Writing the export stream failed.", w.bytes);
        }
        done += limit;
    }
    Publish(progress, CodeExportPhase::Assembly, total, total, 0, w.bytes);
    CodeExportResult out; out.success = true; out.path = req.outputPath;
    out.bytesWritten = w.bytes; out.message = "Assembly export generated successfully.";
    return out;
}

std::vector<std::string> SplitLines(const std::string& s) {
    std::vector<std::string> out;
    size_t p = 0;
    while (p < s.size()) {
        size_t e = s.find('\n', p);
        if (e == std::string::npos) e = s.size();
        std::string line = s.substr(p, e - p);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        out.push_back(std::move(line));
        p = e == s.size() ? e : e + 1;
    }
    return out;
}

void ReplaceAll(std::string& s, const std::string& a, const std::string& b) {
    if (a.empty()) return;
    for (size_t p = s.find(a); p != std::string::npos; p = s.find(a, p + b.size()))
        s.replace(p, a.size(), b);
}

bool SimpleDeclaration(const std::string& t, std::string& var) {
    if (t.empty() || t.back() != ';' || t.find('=') != std::string::npos ||
        t.find('(') != std::string::npos || t.find(',') != std::string::npos) return false;
    static const char* prefixes[] = {
        "int ", "void *", "ds_word_t ", "int8_t ", "uint8_t ", "int16_t ",
        "uint16_t ", "int32_t ", "uint32_t ", "int64_t ", "uint64_t "
    };
    bool type = false;
    for (const char* p : prefixes) if (t.rfind(p, 0) == 0) { type = true; break; }
    if (!type) return false;
    size_t end = t.size() - 1;
    while (end && std::isspace((unsigned char)t[end - 1])) --end;
    size_t begin = end;
    while (begin && IsIdentChar(t[begin - 1])) --begin;
    if (begin == end || !IsIdentStart(t[begin])) return false;
    var = t.substr(begin, end - begin);
    return true;
}

std::vector<std::string> CodeIdentifiers(const std::string& line) {
    std::vector<std::string> out;
    bool quote = false, chr = false, escape = false;
    for (size_t i = 0; i < line.size();) {
        if (!quote && !chr && i + 1 < line.size() && line[i] == '/' &&
            (line[i + 1] == '/' || line[i + 1] == '*')) break;
        char c = line[i];
        if (quote || chr) {
            if (escape) escape = false;
            else if (c == '\\') escape = true;
            else if ((quote && c == '"') || (chr && c == '\'')) { quote = chr = false; }
            ++i; continue;
        }
        if (c == '"') { quote = true; ++i; continue; }
        if (c == '\'') { chr = true; ++i; continue; }
        if (IsIdentStart(c) && (i == 0 || !IsIdentChar(line[i - 1]))) {
            size_t e = i + 1; while (e < line.size() && IsIdentChar(line[e])) ++e;
            out.push_back(line.substr(i, e - i)); i = e; continue;
        }
        ++i;
    }
    return out;
}

std::set<std::string> CalledIdentifiers(const std::string& line) {
    std::set<std::string> out;
    for (size_t i = 0; i < line.size();) {
        if (line[i] == '"' || (i + 1 < line.size() && line[i] == '/' && line[i + 1] == '/')) break;
        if (!IsIdentStart(line[i]) || (i && IsIdentChar(line[i - 1]))) { ++i; continue; }
        size_t e = i + 1; while (e < line.size() && IsIdentChar(line[e])) ++e;
        size_t p = e; while (p < line.size() && std::isspace((unsigned char)line[p])) ++p;
        if (p < line.size() && line[p] == '(') out.insert(line.substr(i, e - i));
        i = e;
    }
    return out;
}

struct SymbolTable {
    std::map<uint64_t, std::string> original;
    std::map<uint64_t, std::string> safe;
};

SymbolTable BuildSymbols(const CodeExportRequest& req) {
    SymbolTable t;
    if (req.binary) for (const auto& im : req.binary->imports())
        if (im.addressKnown && !im.name.empty())
            t.original[im.iatVA] = im.dll + "." + DemangleForLabel(im.name);
    for (const auto& f : req.functions) if (!f.name.empty()) t.original[f.address] = f.name;
    for (const auto& n : req.names) if (!n.second.empty()) t.original[n.first] = n.second;

    std::unordered_set<std::string> used = {
        "ds_word_t","ds_memory_cell","DS_MEM","DS_ADDR","DS_UNMODELED","DS_CALL_INDIRECT",
        "ds_rotl","ds_rotr","ds_bswap","LOBYTE","BYTE1","LOWORD","swap"
    };
    for (const auto& n : t.original) {
        std::string s = SanitizeIdentifier(n.second, n.first);
        if (!used.insert(s).second) {
            s += "_" + Hex(n.first);
            unsigned suffix = 2;
            while (!used.insert(s).second) s += "_" + std::to_string(suffix++);
        }
        t.safe[n.first] = std::move(s);
    }
    for (const auto& f : req.functions) if (!t.safe.count(f.address)) {
        std::string s = SanitizeIdentifier(f.name, f.address);
        if (!used.insert(s).second) {
            s += "_" + Hex(f.address);
            unsigned suffix = 2;
            while (!used.insert(s).second) s += "_" + std::to_string(suffix++);
        }
        t.safe[f.address] = s;
        t.original[f.address] = f.name.empty() ? "sub_" + Hex(f.address) : f.name;
    }
    return t;
}

struct CompiledFunction {
    uint64_t va = 0;
    std::string original, name;
    unsigned argCount = 0;
    std::vector<std::string> lines;
    std::set<std::string> variables, calls, gotos, labels;
};

bool IsArg(const std::string& s, unsigned& number) {
    if (s.size() < 2 || s[0] != 'a') return false;
    unsigned n = 0;
    for (size_t i = 1; i < s.size(); ++i) {
        if (!std::isdigit((unsigned char)s[i])) return false;
        n = n * 10 + (unsigned)(s[i] - '0');
    }
    number = n; return n != 0 && n <= 64;
}

CompiledFunction NormalizeFunction(uint64_t va, const std::string& original,
                                   const std::string& name, const DecompResult& pseudo) {
    CompiledFunction f; f.va = va; f.original = original; f.name = name;
    std::vector<std::string> lines = SplitLines(pseudo.text);
    // The decompiler emits a header, an outer "{", the body, and an outer "}".
    // Completeness diagnostics may precede the header, so locate the structural
    // brace instead of assuming the first two lines are always header + brace.
    size_t begin = lines.size();
    for (size_t i = 0; i < lines.size(); ++i) {
        if (Trim(lines[i]) == "{") { begin = i + 1; break; }
    }
    size_t end = lines.size();
    while (end > begin && Trim(lines[end - 1]).empty()) --end;
    if (end > begin && Trim(lines[end - 1]) == "}") --end;

    // Keep explicit incompleteness warnings visible in compilable output without
    // accidentally treating the decompiler's function header as a statement.
    for (size_t i = 0; i < lines.size() && i + 1 < begin; ++i)
        if (Trim(lines[i]).rfind("// WARNING:", 0) == 0)
            f.lines.push_back("    " + Trim(lines[i]));

    for (size_t i = begin; i < end; ++i) {
        std::string line = lines[i];
        std::string indent = line.substr(0, line.find_first_not_of(" \t"));
        std::string t = Trim(line);
        if (t.empty()) { f.lines.push_back({}); continue; }

        ReplaceAll(line, "unsigned __int64", "uint64_t");
        ReplaceAll(line, "unsigned __int32", "uint32_t");
        ReplaceAll(line, "unsigned __int16", "uint16_t");
        ReplaceAll(line, "unsigned __int8",  "uint8_t");
        ReplaceAll(line, "signed __int64", "int64_t");
        ReplaceAll(line, "signed __int32", "int32_t");
        ReplaceAll(line, "signed __int16", "int16_t");
        ReplaceAll(line, "signed __int8",  "int8_t");
        ReplaceAll(line, "__int64", "ds_word_t");
        ReplaceAll(line, "__int32", "int32_t");
        ReplaceAll(line, "__int16", "int16_t");
        ReplaceAll(line, "__int8",  "int8_t");
        ReplaceAll(line, "_rotl(", "ds_rotl(");
        ReplaceAll(line, "_rotr(", "ds_rotr(");
        ReplaceAll(line, "bswap(", "ds_bswap(");
        ReplaceAll(line, "*(", "DS_MEM(");
        ReplaceAll(line, "&(", "DS_ADDR(");
        t = Trim(line);

        std::string decl;
        if (SimpleDeclaration(t, decl)) { f.variables.insert(decl); continue; }
        if (t.rfind("__asm", 0) == 0 || t.find("(*") != std::string::npos) {
            f.lines.push_back(indent + "DS_UNMODELED(\"" + EscapeCString(t) + "\");");
            continue;
        }
        // Register-pair pseudo assignments such as rdx:rax are descriptive but not C.
        size_t colon = t.find(':');
        if (colon != std::string::npos && t.rfind("case ", 0) != 0 && t != "default:" &&
            t.back() != ':' && t.find('?') == std::string::npos) {
            f.lines.push_back(indent + "DS_UNMODELED(\"" + EscapeCString(t) + "\");");
            continue;
        }
        if (t == "return;") line = indent + "return (ds_word_t)0;";

        std::string nt = Trim(line);
        if (nt.rfind("goto ", 0) == 0) {
            size_t a = 5, e = a; while (e < nt.size() && IsIdentChar(nt[e])) ++e;
            if (e > a) f.gotos.insert(nt.substr(a, e - a));
        }
        if (!nt.empty() && nt.back() == ':') {
            std::string l = nt.substr(0, nt.size() - 1);
            if (!l.empty() && l.rfind("case ", 0) != 0 && l != "default" && IsIdentStart(l[0])) f.labels.insert(l);
        }
        auto calls = CalledIdentifiers(line);
        f.calls.insert(calls.begin(), calls.end());
        for (const std::string& id : CodeIdentifiers(line)) {
            unsigned arg = 0;
            if (IsArg(id, arg)) { f.argCount = std::max(f.argCount, arg); continue; }
            f.variables.insert(id);
        }
        f.lines.push_back(std::move(line));
    }
    return f;
}

const std::unordered_set<std::string>& NonVariables() {
    static std::unordered_set<std::string> k = [] {
        std::unordered_set<std::string> s = CKeywords();
        const char* extra[] = {
            "ds_word_t","int8_t","uint8_t","int16_t","uint16_t","int32_t","uint32_t",
            "int64_t","uint64_t","intptr_t","uintptr_t","NULL","DS_MEM","DS_ADDR","DS_UNMODELED",
            "DS_CALL_INDIRECT","ds_rotl","ds_rotr","ds_bswap","LOBYTE","BYTE1","LOWORD","swap",
            "true","false"
        };
        for (const char* p : extra) s.insert(p);
        return s;
    }();
    return k;
}

void EmitPreamble(Writer& w, const CodeExportRequest& req) {
    w.line("/* DisasmStudio self-contained compilable C export.");
    w.line(" * Source: " + BlockComment(req.sourceName.empty() ? req.binary->path() : req.sourceName));
    w.line(" * Architecture: " + std::string(ArchName(req.arch)));
    w.line(" * This is a best-effort semantic translation; DS_UNMODELED marks instructions");
    w.line(" * which the lightweight decompiler could not express portably. */");
    w.line("#include <stdint.h>");
    w.line("#include <stddef.h>");
    w.line();
    w.line("typedef uintptr_t ds_word_t;");
    w.line("static ds_word_t ds_memory_cell;");
    w.line("#define DS_MEM(address) (ds_memory_cell)");
    w.line("#define DS_ADDR(value) ((ds_word_t)(value))");
    w.line("#define DS_UNMODELED(text) ((void)0)");
    w.line("#define DS_CALL_INDIRECT(address) ((ds_word_t)0)");
    w.line("#define LOBYTE(x) ((uint8_t)((x) & 0xffu))");
    w.line("#define BYTE1(x) ((uint8_t)(((x) >> 8) & 0xffu))");
    w.line("#define LOWORD(x) ((uint16_t)((x) & 0xffffu))");
    w.line("#define swap(a,b) do { ds_word_t ds_swap_tmp = (ds_word_t)(a); (a) = (b); (b) = ds_swap_tmp; } while (0)");
    w.line("static ds_word_t ds_rotl(ds_word_t x, unsigned n) { unsigned b=(unsigned)(sizeof(x)*8u); n%=b; return n ? (x<<n)|(x>>(b-n)) : x; }");
    w.line("static ds_word_t ds_rotr(ds_word_t x, unsigned n) { unsigned b=(unsigned)(sizeof(x)*8u); n%=b; return n ? (x>>n)|(x<<(b-n)) : x; }");
    w.line("static ds_word_t ds_bswap(ds_word_t x) { ds_word_t r=0; size_t i; for(i=0;i<sizeof(x);++i){ r=(r<<8)|(x&0xffu); x>>=8; } return r; }");
    w.line();
}

CodeExportResult GenerateC(const CodeExportRequest& req, IDisassembler& dis,
                           Writer& w, const CodeExportCancelFn& cancelled,
                           const CodeExportProgressFn& progress) {
    if (req.arch == Arch::GML)
        return Failure(req, "GML source reconstruction is unavailable; export the bytecode assembly instead.");
    if (!ArchIsX86_32Or64(req.arch) && req.cStyle == CodeExportCStyle::Compilable)
        return Failure(req, "Self-contained compilable C currently requires x86/x64; readable pseudocode remains available.");
    DecoderConfig decoderConfig;
    decoderConfig.engine = req.engine;
    decoderConfig.arch = req.arch;
    decoderConfig.byteOrder = req.byteOrder;
    decoderConfig.features = req.decoderFeatures;
    const auto all = SortedFunctions(req);
    const auto funcs = SelectedFunctions(req, all);
    if (funcs.empty()) return Failure(req, req.scope == CodeExportScope::Function
        ? "The selected function was not present in the export snapshot."
        : "No analyzed functions are available to export.");

    DecompileNameMap readableNames = CompleteNames(req);
    const NoreturnCallResolver noreturn = ExportNoreturnResolver(req);
    Publish(progress, CodeExportPhase::Decompiling, 0, funcs.size(), funcs.front().address, w.bytes);
    if (req.cStyle == CodeExportCStyle::Readable) {
        w.line("/* DisasmStudio readable pseudo-C export.");
        w.line(" * Source: " + BlockComment(req.sourceName.empty() ? req.binary->path() : req.sourceName));
        w.line(" * Architecture: " + std::string(ArchName(req.arch)) + " */");
        w.line();
        for (size_t i = 0; i < funcs.size(); ++i) {
            if ((cancelled && cancelled()) ||
                (req.expectedImageRevision && req.binary->imageRevision() != req.expectedImageRevision))
                return Failure(req, "Export cancelled because the image changed.", w.bytes, true);
            const auto& f = funcs[i];
            Publish(progress, CodeExportPhase::Decompiling, i, funcs.size(), f.address, w.bytes);
            uint64_t span = FunctionSpan(*req.binary, f, all);
            if (!span) { w.line("// Function 0x" + Hex(f.address) + " is not file-backed."); continue; }
            uint64_t end = 0;
            if (!CheckedAddressAdd(f.address, span, end)) {
                w.line("// Function extent crosses the address-space limit.");
                continue;
            }
            DecompResult d = DecompileRegion(
                *req.binary, dis, decoderConfig, f.address, end,
                &readableNames, f.signature, noreturn, &f.chunks,
                f.ownershipTruncated, f.callingConvention);
            w.line("// -----------------------------------------------------------------------------");
            w.line("// Discovery: " + FunctionDiscoveryMetadata(f));
            auto c = req.comments.find(f.address);
            if (c != req.comments.end()) w.line("// Analyst comment: " + OneLine(c->second));
            w.put(d.text.empty() ? "// Nothing decoded for this function.\n" : d.text);
            w.line();
            if (!w.ok) return Failure(req, "Writing the export stream failed.", w.bytes);
        }
        Publish(progress, CodeExportPhase::Decompiling, funcs.size(), funcs.size(), 0, w.bytes);
        CodeExportResult r; r.success = true; r.path = req.outputPath; r.bytesWritten = w.bytes;
        r.message = "Readable C export generated successfully."; return r;
    }

    SymbolTable symbols = BuildSymbols(req);
    DecompileNameMap safeNames;
    for (const auto& n : symbols.safe) safeNames[n.first] = n.second;
    std::vector<CompiledFunction> compiled;
    compiled.reserve(funcs.size());
    for (size_t i = 0; i < funcs.size(); ++i) {
        if ((cancelled && cancelled()) ||
            (req.expectedImageRevision && req.binary->imageRevision() != req.expectedImageRevision))
            return Failure(req, "Export cancelled because the image changed.", w.bytes, true);
        const auto& f = funcs[i];
        Publish(progress, CodeExportPhase::Decompiling, i, funcs.size(), f.address, w.bytes);
        uint64_t span = FunctionSpan(*req.binary, f, all);
        DecompResult d;
        uint64_t end = 0;
        if (span && CheckedAddressAdd(f.address, span, end))
            d = DecompileRegion(*req.binary, dis, decoderConfig, f.address, end,
                                &safeNames, f.signature, noreturn, &f.chunks,
                                f.ownershipTruncated, f.callingConvention);
        const std::string original = symbols.original.count(f.address)
                                   ? symbols.original[f.address] : ("sub_" + Hex(f.address));
        const std::string safe = symbols.safe.count(f.address)
                               ? symbols.safe[f.address] : SanitizeIdentifier(original, f.address);
        compiled.push_back(NormalizeFunction(f.address, original, safe, d));
    }

    EmitPreamble(w, req);
    std::set<std::string> localNames;
    for (const auto& f : compiled) localNames.insert(f.name);
    std::set<std::string> externalCalls;
    for (const auto& f : compiled) for (const auto& c : f.calls)
        if (!localNames.count(c) && !NonVariables().count(c) && !CKeywords().count(c)) externalCalls.insert(c);

    w.line("/* Forward declarations. Empty parameter lists deliberately preserve unknown prototypes. */");
    for (const auto& f : compiled) w.line("static ds_word_t " + f.name + "();");
    for (const auto& c : externalCalls)
        w.line("static ds_word_t " + SanitizeIdentifier(c, 0) + "() { return (ds_word_t)0; }");
    w.line();

    for (size_t i = 0; i < compiled.size(); ++i) {
        if (cancelled && cancelled())
            return Failure(req, "Export cancelled; the destination was left unchanged.", w.bytes, true);
        CompiledFunction& f = compiled[i];
        const CodeExportFunction& metadata = funcs[i];
        Publish(progress, CodeExportPhase::Decompiling, i, compiled.size(), f.va, w.bytes);
        w.line("/* Original symbol: " + BlockComment(f.original) + " @ 0x" + Hex(f.va) + " */");
        w.line("/* Discovery: " + BlockComment(FunctionDiscoveryMetadata(metadata)) + " */");
        w.put("static ds_word_t " + f.name + "(");
        if (!f.argCount) w.put("void");
        for (unsigned a = 1; a <= f.argCount; ++a) {
            if (a > 1) w.put(", ");
            w.put("ds_word_t a" + std::to_string(a));
        }
        w.line(")");
        w.line("{");
        for (auto it = f.variables.begin(); it != f.variables.end();) {
            const std::string v = *it;
            unsigned a = 0;
            if (IsArg(v, a) || NonVariables().count(v) || CKeywords().count(v) ||
                f.calls.count(v) || f.labels.count(v) || f.gotos.count(v) || localNames.count(v))
                it = f.variables.erase(it);
            else ++it;
        }
        for (const std::string& v : f.variables) w.line("    ds_word_t " + v + " = (ds_word_t)0;");
        if (!f.variables.empty()) w.line();
        for (const std::string& line : f.lines) w.line(line);
        for (const std::string& target : f.gotos) if (!f.labels.count(target)) {
            w.line(target + ":");
            w.line("    DS_UNMODELED(\"external or recovered goto target\");");
        }
        w.line("    return (ds_word_t)0;");
        w.line("}");
        w.line();
        if (!w.ok) return Failure(req, "Writing the export stream failed.", w.bytes);
    }
    Publish(progress, CodeExportPhase::Decompiling, compiled.size(), compiled.size(), 0, w.bytes);
    CodeExportResult r; r.success = true; r.path = req.outputPath; r.bytesWritten = w.bytes;
    r.message = "Self-contained C export generated successfully."; return r;
}

// Reserving a directory is an atomic, portable exclusive-create operation. The
// stream and rollback file live inside that owned namespace, so independent
// documents/processes cannot truncate or remove one another's temporary files.
struct ExportScratch {
    fs::path directory, temp, backup;

    ~ExportScratch() { cleanup(); }

    void cleanup() noexcept {
        std::error_code ec;
        if (!temp.empty()) fs::remove(temp, ec);
        // Never recursively remove: a failed rollback retains the previous
        // destination in `backup` for recovery.
        if (!directory.empty()) fs::remove(directory, ec);
        temp.clear();
        directory.clear();
    }

    bool reserve(const fs::path& dest, std::string& error) {
        static std::atomic<uint64_t> sequence{0};
        for (unsigned attempt = 0; attempt < 32; ++attempt) {
            fs::path candidate = dest;
            candidate += ".disasmstudio-tmp-" + std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()) + "-" +
                std::to_string(sequence.fetch_add(1, std::memory_order_relaxed));
            std::error_code ec;
            if (fs::create_directory(candidate, ec)) {
                directory = std::move(candidate);
                temp = directory / "output";
                backup = directory / "previous";
                return true;
            }
            if (ec && ec != std::errc::file_exists) {
                error = "Could not reserve temporary export storage: " + ec.message();
                return false;
            }
        }
        error = "Could not reserve unique temporary export storage.";
        return false;
    }
};

bool CommitTempFile(const fs::path& temp, const fs::path& dest, const fs::path& backup,
                    std::string& error) {
    // Multiple document workers may target the same destination. Keep the short
    // replace/rollback sequence indivisible with respect to our other exports.
    static std::mutex commitMutex;
    std::lock_guard<std::mutex> lock(commitMutex);
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(dest, ec);
    if (status.type() == fs::file_type::not_found) {
        ec.clear(); fs::rename(temp, dest, ec);
        if (!ec) return true;
        error = "Could not move the completed temporary export into place: " + ec.message();
        return false;
    }
    if (ec || !fs::is_regular_file(status)) {
        error = ec ? "Could not inspect the export destination: " + ec.message()
                   : "The export destination is not a regular file.";
        return false;
    }
    fs::rename(dest, backup, ec);
    if (ec) { error = "Could not preserve the existing destination: " + ec.message(); return false; }
    ec.clear(); fs::rename(temp, dest, ec);
    if (ec) {
        std::error_code rollback;
        fs::rename(backup, dest, rollback);
        error = "Could not replace the destination with the completed export: " + ec.message();
        if (rollback) {
            const auto recoveryPath = backup.u8string();
            error += ". The previous destination was retained at ";
            error.append(reinterpret_cast<const char*>(recoveryPath.data()), recoveryPath.size());
        }
        return false;
    }
    fs::remove(backup, ec);
    return true;
}

} // namespace

const char* CodeExportPhaseName(CodeExportPhase phase) {
    switch (phase) {
        case CodeExportPhase::Idle:        return "Idle";
        case CodeExportPhase::Preparing:   return "Preparing export";
        case CodeExportPhase::Assembly:    return "Saving assembly";
        case CodeExportPhase::Decompiling: return "Decompiling functions";
        case CodeExportPhase::Finalizing:  return "Finalizing file";
    }
    return "Exporting";
}

CodeExportResult GenerateCodeExport(const CodeExportRequest& request,
                                    IDisassembler& decoder, std::ostream& out,
                                    const CodeExportCancelFn& cancelled,
                                    const CodeExportProgressFn& progress) {
    if (!request.binary || !request.binary->loaded())
        return Failure(request, "No loaded binary was supplied for export.");
    if (request.expectedImageRevision &&
        request.binary->imageRevision() != request.expectedImageRevision)
        return Failure(request, "The binary changed before the export began.");
    Writer w{ out };
    Publish(progress, CodeExportPhase::Preparing, 0, 0, 0, 0);
    CodeExportResult r = request.format == CodeExportFormat::C
                       ? GenerateC(request, decoder, w, cancelled, progress)
                       : GenerateAssembly(request, decoder, w, cancelled, progress);
    r.bytesWritten = w.bytes;
    if (r.success && !w.ok) {
        r.success = false;
        r.message = "Writing the export stream failed.";
    }
    return r;
}

struct CodeExportService::Impl {
    struct Job { CodeExportRequest request; uint64_t token = 0; };

    explicit Impl(DecoderFactory f) : factory(std::move(f)) {
        // Start only after every member has been constructed.  Starting from the
        // initializer list allowed the new thread to observe mutex/queue members
        // whose constructors had not run yet (member initialization follows
        // declaration order, not initializer-list order).
        worker = std::thread([this] { threadEntry(); });
    }
    ~Impl() {
        {
            std::lock_guard<std::mutex> lk(mtx);
            quit = true; hasJob = false; cancelToken.fetch_add(1, std::memory_order_acq_rel);
        }
        cv.notify_all();
        if (worker.joinable()) worker.join();
    }

    void setProgress(const CodeExportProgress& p) {
        phase.store((uint8_t)p.phase, std::memory_order_release);
        current.store(p.current, std::memory_order_relaxed);
        total.store(p.total, std::memory_order_relaxed);
        functionVA.store(p.functionVA, std::memory_order_relaxed);
        bytes.store(p.bytesWritten, std::memory_order_relaxed);
    }
    void idleProgress() {
        CodeExportProgress p; setProgress(p);
    }

    void publishFatalFailure(const char* message) noexcept {
        try {
            std::lock_guard<std::mutex> lk(mtx);
            running = false;
            hasJob = false;
            quit.store(true, std::memory_order_release);
            idleProgress();
            CodeExportResult result;
            result.path = job.request.outputPath;
            result.message = message;
            results.push_back(std::move(result));
            if (results.size() > 8) results.pop_front();
        } catch (...) {
            // An allocation failure may prevent even the bounded diagnostic from
            // being retained, but the thread boundary must still never terminate
            // the application.
            quit.store(true, std::memory_order_release);
            idleProgress();
        }
        idle.notify_all();
        cv.notify_all();
    }

    void threadEntry() noexcept {
        try {
            run();
        } catch (const std::exception&) {
            publishFatalFailure("The code-export worker stopped after an unexpected internal exception.");
        } catch (...) {
            publishFatalFailure("The code-export worker stopped after an unknown internal exception.");
        }
    }

    void run() {
        for (;;) {
            Job j;
            {
                std::unique_lock<std::mutex> lk(mtx);
                cv.wait(lk, [&] { return quit.load(std::memory_order_acquire) || hasJob; });
                if (quit.load(std::memory_order_acquire)) return;
                j = std::move(job); hasJob = false; running = true;
            }

            CodeExportResult result;
            result.path = j.request.outputPath;
            CodeExportProgress prep; prep.phase = CodeExportPhase::Preparing; setProgress(prep);
            ExportScratch scratch;
            const auto isCancelled = [&] {
                return cancelToken.load(std::memory_order_acquire) != j.token ||
                       quit.load(std::memory_order_acquire);
            };

            try {
                if (!j.request.binary || !j.request.binary->loaded()) {
                    result.message = "The binary is no longer loaded.";
                } else if (j.request.expectedImageRevision &&
                           j.request.binary->imageRevision() != j.request.expectedImageRevision) {
                    result.message = "The binary changed before the export began.";
                } else {
                    DecoderConfig decoder;
                    decoder.engine = j.request.engine;
                    decoder.arch = j.request.arch;
                    decoder.byteOrder = j.request.byteOrder;
                    decoder.features = j.request.decoderFeatures;
                    decoder = DecoderConfigForImage(*j.request.binary, decoder);
                    j.request.engine = decoder.engine;
                    j.request.arch = decoder.arch;
                    j.request.byteOrder = decoder.byteOrder;
                    j.request.decoderFeatures = decoder.features;
                    std::unique_ptr<IDisassembler> dis = factory ? factory(decoder) : nullptr;
                    if (dis && j.request.arch == Arch::GML && j.request.binary->gameMakerArchive())
                        AttachGameMakerArchive(*dis, j.request.binary->gameMakerArchive());
                    if (!dis) result.message = "Could not create an independent export decoder.";
                    else if (!dis->ready()) {
                        result.message = "Could not initialize the export decoder";
                        if (!dis->errorMessage().empty()) {
                            result.message += ": ";
                            result.message.append(dis->errorMessage());
                        }
                    }
                    else {
                        if (j.request.arch == Arch::JVM && j.request.binary->javaClass())
                            AttachJvmClass(*dis, j.request.binary->javaClass());
                        fs::path dest = PathFromUtf8(j.request.outputPath);
                        std::error_code ec;
                        if (!dest.parent_path().empty()) fs::create_directories(dest.parent_path(), ec);
                        if (ec) result.message = "Could not create the export directory: " + ec.message();
                        else if (scratch.reserve(dest, result.message)) {
                            std::ofstream file(scratch.temp, std::ios::binary | std::ios::trunc);
                            if (!file) result.message = "Could not open a temporary export file beside the destination.";
                            else {
                                result = GenerateCodeExport(j.request, *dis, file, isCancelled,
                                    [this](const CodeExportProgress& p) { setProgress(p); });
                                file.flush();
                                if (!file && result.success) {
                                    result.success = false; result.message = "Flushing the temporary export file failed.";
                                }
                                file.close();
                                if (!file && result.success) {
                                    result.success = false; result.message = "Closing the temporary export file failed.";
                                }
                                if (isCancelled() && result.success) {
                                    result.success = false; result.cancelled = true;
                                    result.message = "Export cancelled; the destination was left unchanged.";
                                }
                                if (result.success) {
                                    CodeExportProgress final;
                                    final.phase = CodeExportPhase::Finalizing;
                                    final.current = final.total = 1; final.bytesWritten = result.bytesWritten;
                                    setProgress(final);
                                    std::string err;
                                    if (!CommitTempFile(scratch.temp, dest, scratch.backup, err)) {
                                        result.success = false; result.message = std::move(err);
                                    } else {
                                        result.path = j.request.outputPath;
                                        result.message = "Exported " + std::to_string(result.bytesWritten) +
                                                         " bytes to " + result.path;
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (const std::exception& error) {
                result.success = false;
                result.message = std::string("Code export failed safely: ") + error.what();
            } catch (...) {
                result.success = false;
                result.message = "Code export failed safely after an unknown worker exception.";
            }
            scratch.cleanup();

            {
                std::lock_guard<std::mutex> lk(mtx);
                results.push_back(std::move(result));
                if (results.size() > 8) results.pop_front();
                running = false;
                idleProgress();
            }
            idle.notify_all();
        }
    }

    DecoderFactory factory;
    std::thread worker;
    mutable std::mutex mtx;
    std::condition_variable cv, idle;
    Job job;
    bool hasJob = false, running = false;
    std::atomic<bool> quit{false};
    std::deque<CodeExportResult> results;
    std::atomic<uint64_t> cancelToken{1};
    std::atomic<uint8_t> phase{(uint8_t)CodeExportPhase::Idle};
    std::atomic<uint64_t> current{0}, total{0}, functionVA{0}, bytes{0};
};

CodeExportService::CodeExportService(DecoderFactory factory)
    : impl_(std::make_unique<Impl>(std::move(factory))) {}
CodeExportService::CodeExportService(LegacyDecoderFactory factory)
    : CodeExportService(DecoderFactory(
          [legacy = std::move(factory)](const DecoderConfig& config) {
              return legacy && LegacyDecoderFactoryCanRepresent(config)
                   ? legacy(config.engine, config.arch) : nullptr;
          })) {}
CodeExportService::~CodeExportService() = default;

bool CodeExportService::request(CodeExportRequest request) {
    if (!impl_ || !request.binary || !request.binary->loaded() || request.outputPath.empty()) return false;
    std::lock_guard<std::mutex> lk(impl_->mtx);
    if (impl_->running || impl_->hasJob || impl_->quit.load(std::memory_order_acquire)) return false;
    if (!request.expectedImageRevision) request.expectedImageRevision = request.binary->imageRevision();
    impl_->job.request = std::move(request);
    impl_->job.token = impl_->cancelToken.load(std::memory_order_acquire);
    impl_->hasJob = true;
    CodeExportProgress p; p.phase = CodeExportPhase::Preparing; impl_->setProgress(p);
    impl_->cv.notify_one();
    return true;
}

bool CodeExportService::pending() const {
    if (!impl_) return false;
    std::lock_guard<std::mutex> lk(impl_->mtx);
    return impl_->hasJob || impl_->running;
}

CodeExportProgress CodeExportService::progress() const {
    CodeExportProgress p;
    if (!impl_) return p;
    p.phase = (CodeExportPhase)impl_->phase.load(std::memory_order_acquire);
    p.current = impl_->current.load(std::memory_order_relaxed);
    p.total = impl_->total.load(std::memory_order_relaxed);
    p.functionVA = impl_->functionVA.load(std::memory_order_relaxed);
    p.bytesWritten = impl_->bytes.load(std::memory_order_relaxed);
    return p;
}

bool CodeExportService::tryTakeResult(CodeExportResult& out) {
    if (!impl_) return false;
    std::lock_guard<std::mutex> lk(impl_->mtx);
    if (impl_->results.empty()) return false;
    out = std::move(impl_->results.front()); impl_->results.pop_front();
    return true;
}

void CodeExportService::cancel() {
    if (!impl_) return;
    std::lock_guard<std::mutex> lk(impl_->mtx);
    impl_->cancelToken.fetch_add(1, std::memory_order_acq_rel);
    if (impl_->hasJob) {
        CodeExportResult r;
        r.cancelled = true; r.path = impl_->job.request.outputPath;
        r.message = "Export cancelled; the destination was left unchanged.";
        impl_->results.push_back(std::move(r));
        impl_->hasJob = false;
        if (!impl_->running) impl_->idleProgress();
    }
    impl_->cv.notify_all();
}

void CodeExportService::cancelAndWaitIdle() {
    if (!impl_) return;
    std::unique_lock<std::mutex> lk(impl_->mtx);
    impl_->cancelToken.fetch_add(1, std::memory_order_acq_rel);
    impl_->hasJob = false;
    impl_->results.clear();
    impl_->cv.notify_all();
    impl_->idle.wait(lk, [&] { return !impl_->running; });
    impl_->results.clear();
    impl_->idleProgress();
}

} // namespace ds
