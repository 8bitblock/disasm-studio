#include "Project.h"
#include "Json.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace ds {

namespace fs = std::filesystem;
using json::Value;

// ---------------------------------------------------------------- helpers ---

static std::string hexU64(uint64_t v) {
    char b[20]; std::snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v); return b;
}
static uint64_t parseU64(const std::string& s) {
    const char* p = s.c_str();
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) p += 2;
    errno = 0;
    char* end = nullptr;
    unsigned long long v = std::strtoull(p, &end, 16);
    if (end == p || errno == ERANGE) return 0;   // no hex digits parsed, or overflow -> 0 (don't fabricate)
    return (uint64_t)v;
}
static std::string bytesToHex(const std::vector<uint8_t>& b) {
    std::string s; s.reserve(b.size() * 3);
    for (size_t i = 0; i < b.size(); ++i) { char t[4]; std::snprintf(t, sizeof(t), i ? " %02X" : "%02X", b[i]); s += t; }
    return s;
}
static std::vector<uint8_t> hexToBytes(const std::string& s) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i < s.size();) {
        if (std::isspace((unsigned char)s[i])) { ++i; continue; }
        // Require a full two-hex-digit byte; a lone trailing nibble ("4") is malformed,
        // not 0x04 — stop rather than fabricate a wrong patch byte.
        if (i + 1 >= s.size() || !std::isxdigit((unsigned char)s[i]) || !std::isxdigit((unsigned char)s[i + 1])) break;
        char h[3] = { s[i], s[i + 1], 0 };
        unsigned v = 0; std::sscanf(h, "%x", &v);
        out.push_back((uint8_t)v); i += 2;
    }
    return out;
}

// ------------------------------------------------------------ serialize -----

std::string SerializeProject(const ProjectState& st) {
    Value root = Value::Obj();
    root.set("version",        Value::Int(1));
    root.set("hash",           Value::Str(hexU64(st.hash)));
    root.set("binaryPath",     Value::Str(st.binaryPath));
    root.set("arch",           Value::Str(st.arch));
    root.set("engine",         Value::Str(st.engine));
    root.set("name",           Value::Str(st.name));
    root.set("status",         Value::Str(st.status));
    root.set("lastOpenedUnix", Value::Int(st.lastOpenedUnix));
    root.set("lastCursor",     Value::Str(hexU64(st.lastCursor)));
    root.set("notes",          Value::Str(st.notes));

    // names / comments: arrays of {a, v} sorted by address for stable output.
    auto dumpMap = [](const std::unordered_map<uint64_t, std::string>& m) {
        std::vector<std::pair<uint64_t, std::string>> v(m.begin(), m.end());
        std::sort(v.begin(), v.end());
        Value arr = Value::Arr();
        for (auto& kv : v) { Value e = Value::Obj(); e.set("a", Value::Str(hexU64(kv.first))); e.set("v", Value::Str(kv.second)); arr.push(std::move(e)); }
        return arr;
    };
    root.set("names",    dumpMap(st.names));
    root.set("comments", dumpMap(st.comments));
    root.set("algorithmLabels", dumpMap(st.algorithmLabels));

    {   // Labels for non-address targets (Java classes/methods/fields/resources/events).
        Value arr = Value::Arr();
        auto labels = st.labels;
        std::sort(labels.begin(), labels.end(), [](const PjLabel& a, const PjLabel& b) {
            if (a.targetKind != b.targetKind) return a.targetKind < b.targetKind;
            if (a.target != b.target) return a.target < b.target;
            return a.label < b.label;
        });
        for (const auto& l : labels) {
            Value e = Value::Obj();
            e.set("kind", Value::Str(l.targetKind));
            e.set("target", Value::Str(l.target));
            e.set("label", Value::Str(l.label));
            e.set("confidence", Value::Num(l.confidence));
            e.set("note", Value::Str(l.note));
            arr.push(std::move(e));
        }
        root.set("labels", std::move(arr));
    }

    {   // Local connection framework config + accepted event timeline.
        Value c = Value::Obj();
        c.set("enabled", Value::Bool(st.connection.enabled));
        c.set("localhostOnly", Value::Bool(st.connection.localhostOnly));
        c.set("authEnabled", Value::Bool(st.connection.authEnabled));
        c.set("accessToken", Value::Str(st.connection.accessToken));
        root.set("connection", std::move(c));

        Value arr = Value::Arr();
        for (const ConnectionEnvelope& e : st.connectionEvents)
            arr.push(ConnectionEnvelopeToJsonValue(e));
        root.set("connectionEvents", std::move(arr));
    }

    {
        Value arr = Value::Arr();
        auto bm = st.bookmarks;
        std::sort(bm.begin(), bm.end(), [](const PjBookmark& a, const PjBookmark& b){ return a.address < b.address; });
        for (auto& b : bm) { Value e = Value::Obj(); e.set("a", Value::Str(hexU64(b.address))); e.set("label", Value::Str(b.label)); arr.push(std::move(e)); }
        root.set("bookmarks", std::move(arr));
    }
    {
        Value arr = Value::Arr();
        auto bps = st.breakpoints;
        std::sort(bps.begin(), bps.end());
        for (uint64_t a : bps) {
            Value e = Value::Obj();
            e.set("a", Value::Str(hexU64(a)));
            auto it = st.bpConditions.find(a);
            if (it != st.bpConditions.end() && !it->second.empty()) e.set("cond", Value::Str(it->second));
            auto en = st.bpEveryN.find(a);
            if (en != st.bpEveryN.end() && en->second > 1) e.set("everyN", Value::Int(en->second));
            arr.push(std::move(e));
        }
        root.set("breakpoints", std::move(arr));
    }
    {
        Value arr = Value::Arr();
        auto ps = st.patches;
        std::sort(ps.begin(), ps.end(), [](const PjPatch& a, const PjPatch& b){ return a.address < b.address; });
        for (auto& p : ps) {
            Value e = Value::Obj();
            e.set("a",     Value::Str(hexU64(p.address)));
            e.set("orig",  Value::Str(bytesToHex(p.orig)));
            e.set("bytes", Value::Str(bytesToHex(p.bytes)));
            arr.push(std::move(e));
        }
        root.set("patches", std::move(arr));
    }
    {
        Value arr = Value::Arr();
        for (auto& w : st.watches) { Value e = Value::Obj(); e.set("v", Value::Str(w)); arr.push(std::move(e)); }
        root.set("watches", std::move(arr));
    }
    {   // F1 synthesis results
        Value arr = Value::Arr();
        auto sv = st.syntheses;
        std::sort(sv.begin(), sv.end(), [](const PjSynthesis& a, const PjSynthesis& b){ return a.address < b.address; });
        for (auto& s : sv) {
            Value e = Value::Obj();
            e.set("a",       Value::Str(hexU64(s.address)));
            e.set("size",    Value::Int(s.size));
            e.set("pseudoC", Value::Str(s.pseudoC));
            e.set("sp",      Value::Int(s.samplesPassed));
            e.set("st",      Value::Int(s.samplesTotal));
            e.set("z3",      Value::Bool(s.z3Equivalent));
            e.set("why",     Value::Str(s.reasoning));
            arr.push(std::move(e));
        }
        root.set("syntheses", std::move(arr));
    }
    {   // F2 inline hot-patch sources
        Value arr = Value::Arr();
        auto hv = st.hotPatches;
        std::sort(hv.begin(), hv.end(), [](const PjHotPatch& a, const PjHotPatch& b){ return a.address < b.address; });
        for (auto& h : hv) {
            Value e = Value::Obj();
            e.set("a",    Value::Str(hexU64(h.address)));
            e.set("lang", Value::Str(h.lang));
            e.set("src",  Value::Str(h.source));
            arr.push(std::move(e));
        }
        root.set("hotPatches", std::move(arr));
    }
    return json::Dump(root, true);
}

bool DeserializeProject(const std::string& text, ProjectState& out) {
    Value root;
    if (!json::Parse(text, root) || !root.isObj()) return false;
    ProjectState st;
    st.hash           = parseU64(root.getStr("hash", "0"));
    st.binaryPath     = root.getStr("binaryPath");
    st.arch           = root.getStr("arch");
    st.engine         = root.getStr("engine");
    st.name           = root.getStr("name");
    st.status         = root.getStr("status", "analyzed");
    st.lastOpenedUnix = root.getInt("lastOpenedUnix");
    st.lastCursor     = parseU64(root.getStr("lastCursor", "0"));
    st.notes          = root.getStr("notes");

    auto loadMap = [&](const char* key, std::unordered_map<uint64_t, std::string>& m) {
        if (const Value* a = root.find(key); a && a->isArr())
            for (const auto& e : a->arr) if (e.isObj()) m[parseU64(e.getStr("a", "0"))] = e.getStr("v");
    };
    loadMap("names",    st.names);
    loadMap("comments", st.comments);
    loadMap("algorithmLabels", st.algorithmLabels);

    if (const Value* a = root.find("labels"); a && a->isArr())
        for (const auto& e : a->arr) if (e.isObj()) {
            PjLabel l;
            l.targetKind = e.getStr("kind");
            l.target     = e.getStr("target");
            l.label      = e.getStr("label");
            l.confidence = (float)e.getInt("confidence", 1);
            if (const Value* cv = e.find("confidence"); cv && cv->isNum())
                l.confidence = (float)cv->num;
            if (l.confidence < 0.0f) l.confidence = 0.0f;
            if (l.confidence > 1.0f) l.confidence = 1.0f;
            l.note = e.getStr("note");
            if (!l.targetKind.empty() && !l.target.empty() && !l.label.empty())
                st.labels.push_back(std::move(l));
        }

    if (const Value* c = root.find("connection"); c && c->isObj()) {
        st.connection.enabled       = c->getBool("enabled", false);
        st.connection.localhostOnly = c->getBool("localhostOnly", true);
        st.connection.authEnabled   = c->getBool("authEnabled", false);
        st.connection.accessToken   = c->getStr("accessToken");
        std::string ignored;
        if (!ValidateConnectionConfig(st.connection, &ignored)) st.connection = ConnectionConfig{};
    }
    if (const Value* a = root.find("connectionEvents"); a && a->isArr())
        for (const auto& e : a->arr) {
            ConnectionEnvelope ev;
            std::string ignored;
            if (ConnectionEnvelopeFromJsonValue(e, ev, &ignored))
                st.connectionEvents.push_back(std::move(ev));
        }

    if (const Value* a = root.find("bookmarks"); a && a->isArr())
        for (const auto& e : a->arr) if (e.isObj()) st.bookmarks.push_back({ parseU64(e.getStr("a", "0")), e.getStr("label") });

    if (const Value* a = root.find("breakpoints"); a && a->isArr())
        for (const auto& e : a->arr) if (e.isObj()) {
            uint64_t addr = parseU64(e.getStr("a", "0"));
            // Keep the breakpoints vector and the bpConditions map 1:1 — a duplicate
            // address would otherwise break that implicit invariant.
            if (std::find(st.breakpoints.begin(), st.breakpoints.end(), addr) != st.breakpoints.end()) continue;
            st.breakpoints.push_back(addr);
            std::string c = e.getStr("cond");
            if (!c.empty()) st.bpConditions[addr] = c;
            int64_t n = e.getInt("everyN");
            if (n > 1 && n <= 0x7FFFFFFF) st.bpEveryN[addr] = (uint32_t)n;
        }

    if (const Value* a = root.find("patches"); a && a->isArr())
        for (const auto& e : a->arr) if (e.isObj()) {
            PjPatch p{ parseU64(e.getStr("a", "0")), hexToBytes(e.getStr("orig")), hexToBytes(e.getStr("bytes")) };
            // Validate before the file splicer trusts these: non-empty, orig and patch
            // the same length, and a sane size cap (a corrupt sidecar mustn't drive a
            // huge / mismatched write into the binary).
            if (p.bytes.empty() || p.bytes.size() != p.orig.size() || p.bytes.size() > (1u << 20)) continue;
            st.patches.push_back(std::move(p));
        }

    if (const Value* a = root.find("watches"); a && a->isArr())
        for (const auto& e : a->arr) if (e.isObj()) { std::string w = e.getStr("v"); if (!w.empty()) st.watches.push_back(w); }

    if (const Value* a = root.find("syntheses"); a && a->isArr())
        for (const auto& e : a->arr) if (e.isObj()) {
            PjSynthesis s;
            s.address       = parseU64(e.getStr("a", "0"));
            s.size          = (uint32_t)e.getInt("size");
            s.pseudoC       = e.getStr("pseudoC");
            s.samplesPassed = (uint32_t)e.getInt("sp");
            s.samplesTotal  = (uint32_t)e.getInt("st");
            s.z3Equivalent  = e.getBool("z3");
            s.reasoning     = e.getStr("why");
            st.syntheses.push_back(std::move(s));
        }

    if (const Value* a = root.find("hotPatches"); a && a->isArr())
        for (const auto& e : a->arr) if (e.isObj()) {
            PjHotPatch h{ parseU64(e.getStr("a", "0")), e.getStr("lang"), e.getStr("src") };
            if (!h.source.empty()) st.hotPatches.push_back(std::move(h));
        }

    out = std::move(st);
    return true;
}

// ------------------------------------------------------------ filesystem ----

std::string ProjectsDir() {
    if (const char* over = std::getenv("DS_PROJECTS_DIR"); over && *over) return over;
    std::string base;
#ifdef _WIN32
    if (const char* appdata = std::getenv("APPDATA"); appdata && *appdata) base = std::string(appdata) + "\\DisasmStudio\\projects";
    else base = "DisasmStudio_projects";
#else
    if (const char* home = std::getenv("HOME"); home && *home) base = std::string(home) + "/.disasmstudio/projects";
    else base = "disasmstudio_projects";
#endif
    return base;
}

std::string ProjectPathForHash(uint64_t hash) {
    std::error_code ec;
    fs::create_directories(ProjectsDir(), ec);
    char name[32]; std::snprintf(name, sizeof(name), "%016llX.json", (unsigned long long)hash);
    return (fs::path(ProjectsDir()) / name).string();
}

static std::string recentsPath() {
    return (fs::path(ProjectsDir()) / "index.json").string();
}

static bool readFile(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss; ss << f.rdbuf(); out = ss.str();
    return true;
}
static bool writeFile(const std::string& path, const std::string& data) {
    std::error_code ec; fs::create_directories(fs::path(path).parent_path(), ec);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(data.data(), (std::streamsize)data.size());
    return (bool)f;
}

bool LoadProject(uint64_t hash, ProjectState& out) {
    if (!hash) return false;
    std::string text;
    if (!readFile(ProjectPathForHash(hash), text)) return false;
    return DeserializeProject(text, out);
}

std::vector<RecentEntry> LoadRecents() {
    std::vector<RecentEntry> recents;
    std::string text;
    if (!readFile(recentsPath(), text)) return recents;
    Value root;
    if (!json::Parse(text, root)) return recents;
    const Value* arr = root.isArr() ? &root : root.find("projects");
    if (!arr || !arr->isArr()) return recents;
    for (const auto& e : arr->arr) {
        if (!e.isObj()) continue;
        RecentEntry r;
        r.hash           = parseU64(e.getStr("hash", "0"));
        r.path           = e.getStr("path");
        r.name           = e.getStr("name");
        r.arch           = e.getStr("arch");
        r.status         = e.getStr("status", "analyzed");
        r.lastOpenedUnix = e.getInt("lastOpenedUnix");
        if (r.hash) recents.push_back(std::move(r));
    }
    return recents;
}

static void writeRecents(const std::vector<RecentEntry>& recents) {
    Value root = Value::Arr();
    for (const auto& r : recents) {
        Value e = Value::Obj();
        e.set("hash",           Value::Str(hexU64(r.hash)));
        e.set("path",           Value::Str(r.path));
        e.set("name",           Value::Str(r.name));
        e.set("arch",           Value::Str(r.arch));
        e.set("status",         Value::Str(r.status));
        e.set("lastOpenedUnix", Value::Int(r.lastOpenedUnix));
        root.push(std::move(e));
    }
    writeFile(recentsPath(), json::Dump(root, true));
}

static void upsertRecent(const ProjectState& st) {
    auto recents = LoadRecents();
    recents.erase(std::remove_if(recents.begin(), recents.end(),
                                 [&](const RecentEntry& r){ return r.hash == st.hash; }), recents.end());
    RecentEntry r;
    r.hash = st.hash; r.path = st.binaryPath; r.arch = st.arch; r.status = st.status;
    r.name = st.name.empty() ? st.binaryPath : st.name;
    r.lastOpenedUnix = st.lastOpenedUnix;
    recents.insert(recents.begin(), std::move(r));   // most-recent first
    if (recents.size() > 50) recents.resize(50);
    writeRecents(recents);
}

bool SaveProject(const ProjectState& st) {
    if (!st.hash) return false;
    // Don't litter %APPDATA% with a sidecar that holds no analysis (just an
    // auto-stamped open time). Still record the open in the recents index so the
    // Projects tab tracks recently-opened binaries; a later save with real
    // annotations writes the sidecar. An existing sidecar (from a prior session
    // that did have content) is left untouched.
    if (!st.hasContent()) { upsertRecent(st); return true; }
    if (!writeFile(ProjectPathForHash(st.hash), SerializeProject(st))) return false;
    upsertRecent(st);
    return true;
}

bool RemoveRecent(uint64_t hash) {
    auto recents = LoadRecents();
    size_t before = recents.size();
    recents.erase(std::remove_if(recents.begin(), recents.end(),
                                 [&](const RecentEntry& r){ return r.hash == hash; }), recents.end());
    writeRecents(recents);
    return recents.size() != before;
}

} // namespace ds
