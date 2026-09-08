#include "Project.h"
#include "AtomicFile.h"
#include "Json.h"
#include "PatchSet.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <new>
#include <stdexcept>
#include <unordered_set>

namespace ds {

namespace fs = std::filesystem;
using json::Value;

// Autosave may commit a sidecar while the Projects tab reads or removes a
// recent entry. Serialize compound read-modify-write transactions so two
// individually atomic replacements cannot still lose a logical update.
static std::recursive_mutex gProjectStoreMutex;

// The writer is admitted by exactly the same budgets as the reader.  Keep the
// limits here (rather than duplicating approximate limits in SaveProject) and
// round-trip every candidate through DeserializeProject before publishing it.
static constexpr json::JsonParseLimits kProjectJsonLimits{
    200,        // nesting depth
    1'000'000,  // complete Value nodes
    64u * 1024u * 1024u, // decoded key/value string bytes
    131'072,    // entries in any one array/object
    kProjectJsonStringTokenBytes, // bytes in any one encoded/decoded string token
    128         // numeric token bytes
};
static constexpr size_t kMaxProjectSidecarBytes = 64u * 1024u * 1024u;
static constexpr size_t kMaxRecentsBytes = 4u * 1024u * 1024u;
static constexpr size_t kMaxPatches = 4096;
static constexpr size_t kMaxPatchBytes = 1u << 20;
static constexpr size_t kMaxTotalPatchBytes = 32u * 1024u * 1024u;
// bytesToHex emits "AA BB": 3*n-1 token bytes.  A persisted patch must fit the
// JSON parser's single-token budget even though its decoded byte span may be
// larger; large in-memory patches are losslessly split at this boundary.
static constexpr size_t kMaxPatchBytesPerHexToken =
    (kProjectJsonLimits.maxStringTokenBytes + 1u) / 3u;

// ---------------------------------------------------------------- helpers ---

static std::string hexU64(uint64_t v) {
    char b[20]; std::snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v); return b;
}
static bool tryParseU64(const std::string& s, uint64_t& out) {
    size_t first = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) first = 2;
    const size_t digits = s.size() - first;
    if (!digits || digits > 16) return false;
    for (size_t i = first; i < s.size(); ++i)
        if (!std::isxdigit(static_cast<unsigned char>(s[i]))) return false;
    const char* p = s.c_str() + first;
    errno = 0;
    char* end = nullptr;
    unsigned long long v = std::strtoull(p, &end, 16);
    if (end == p || !end || *end != '\0' || errno == ERANGE) return false;
    out = static_cast<uint64_t>(v);
    return true;
}
static std::string bytesToHex(const std::vector<uint8_t>& b) {
    std::string s; s.reserve(b.size() * 3);
    for (size_t i = 0; i < b.size(); ++i) { char t[4]; std::snprintf(t, sizeof(t), i ? " %02X" : "%02X", b[i]); s += t; }
    return s;
}

static std::vector<PjPatch> patchesForPersistence(
    const std::vector<PjPatch>& patches) {
    std::vector<PjPatch> result;
    result.reserve(patches.size());

    auto append = [&](PjPatch&& patch) {
        // Consecutive forward-adjacent records commute and can be represented
        // as one record without changing later-wins behavior for any overlap.
        // Never exceed the JSON token budget while merging.
        if (!result.empty()) {
            PjPatch& before = result.back();
            const bool beforeValid = before.orig.size() == before.bytes.size() &&
                before.address <= UINT64_MAX - before.bytes.size();
            const bool patchValid = patch.orig.size() == patch.bytes.size();
            if (beforeValid && patchValid &&
                before.patchSetId == patch.patchSetId &&
                before.address + before.bytes.size() == patch.address &&
                patch.bytes.size() <=
                    kMaxPatchBytesPerHexToken -
                        (std::min)(before.bytes.size(), kMaxPatchBytesPerHexToken)) {
                before.orig.insert(before.orig.end(), patch.orig.begin(), patch.orig.end());
                before.bytes.insert(before.bytes.end(), patch.bytes.begin(), patch.bytes.end());
                return;
            }
        }
        result.push_back(std::move(patch));
    };

    for (const PjPatch& patch : patches) {
        // Leave malformed records intact so the mandatory reader round-trip
        // rejects them; do not silently repair authoritative patch state.
        if (patch.bytes.empty() || patch.orig.size() != patch.bytes.size() ||
            patch.address > UINT64_MAX - patch.bytes.size()) {
            result.push_back(patch);
            continue;
        }
        for (size_t offset = 0; offset < patch.bytes.size();) {
            const size_t count = (std::min)(kMaxPatchBytesPerHexToken,
                                            patch.bytes.size() - offset);
            PjPatch chunk;
            chunk.address = patch.address + offset;
            chunk.patchSetId = patch.patchSetId;
            chunk.orig.assign(patch.orig.begin() + offset,
                              patch.orig.begin() + offset + count);
            chunk.bytes.assign(patch.bytes.begin() + offset,
                               patch.bytes.begin() + offset + count);
            append(std::move(chunk));
            offset += count;
        }
    }
    return result;
}

static bool patchStateFitsPersistenceBudget(
    const std::vector<PjPatch>& patches,
    const std::vector<PjPatchSet>& patchSets) {
    if (!BuildPatchSetPlan(patches, patchSets).success) return false;
    size_t total = 0;
    for (const PjPatch& patch : patches) {
        if (patch.bytes.empty() || patch.orig.size() != patch.bytes.size() ||
            patch.address > UINT64_MAX - patch.bytes.size() ||
            patch.bytes.size() > kMaxTotalPatchBytes -
                (std::min)(total, kMaxTotalPatchBytes))
            return false;
        total += patch.bytes.size();
    }
    const auto persisted = patchesForPersistence(patches);
    return persisted.size() <= kMaxPatches &&
           std::all_of(persisted.begin(), persisted.end(), [](const PjPatch& patch) {
               const size_t encodedBytes = patch.bytes.empty()
                   ? 0 : patch.bytes.size() * 3u - 1u;
               const size_t encodedOrig = patch.orig.empty()
                   ? 0 : patch.orig.size() * 3u - 1u;
               return patch.bytes.size() <= kMaxPatchBytes &&
                      encodedBytes <= kProjectJsonLimits.maxStringTokenBytes &&
                      encodedOrig <= kProjectJsonLimits.maxStringTokenBytes;
           });
}
static bool hexToBytes(const std::string& s, std::vector<uint8_t>& out,
                       size_t maxBytes) {
    out.clear();
    out.reserve(std::min(maxBytes, s.size() / 2));
    for (size_t i = 0; i < s.size();) {
        if (std::isspace((unsigned char)s[i])) { ++i; continue; }
        // Require a full two-hex-digit byte; a lone trailing nibble ("4") is malformed,
        // not 0x04 — stop rather than fabricate a wrong patch byte.
        if (i + 1 >= s.size() || !std::isxdigit((unsigned char)s[i]) ||
            !std::isxdigit((unsigned char)s[i + 1]) || out.size() >= maxBytes)
            return false;
        char h[3] = { s[i], s[i + 1], 0 };
        unsigned v = 0; std::sscanf(h, "%x", &v);
        out.push_back((uint8_t)v); i += 2;
    }
    return true;
}

static bool optionalHexField(const Value& object, const char* key,
                             uint64_t& out, uint64_t defaultValue = 0) {
    const Value* value = object.find(key);
    if (!value) { out = defaultValue; return true; }
    return value->isStr() && tryParseU64(value->str, out);
}

static bool optionalBoundedString(const Value& object, const char* key,
                                  std::string& out, size_t maxBytes,
                                  const char* defaultValue = "") {
    const Value* value = object.find(key);
    if (!value) { out = defaultValue; return true; }
    if (!value->isStr() || value->str.size() > maxBytes) return false;
    out = value->str;
    return true;
}

static bool optionalInt64(const Value& object, const char* key, int64_t& out,
                          int64_t defaultValue = 0) {
    const Value* value = object.find(key);
    if (!value) { out = defaultValue; return true; }
    // JSON stores numbers as double. Stay inside its exact-integer range so a
    // cast cannot overflow or silently change persisted metadata.
    constexpr double kMaxExactInteger = 9'007'199'254'740'991.0;
    if (!value->isNum() || !std::isfinite(value->num) ||
        value->num != std::floor(value->num) ||
        value->num < -kMaxExactInteger || value->num > kMaxExactInteger)
        return false;
    out = static_cast<int64_t>(value->num);
    return true;
}

static bool optionalU32(const Value& object, const char* key, uint32_t& out,
                        uint32_t defaultValue = 0) {
    const Value* value = object.find(key);
    if (!value) { out = defaultValue; return true; }
    if (!value->isNum() || !std::isfinite(value->num) ||
        value->num != std::floor(value->num) || value->num < 0.0 ||
        value->num > static_cast<double>(UINT32_MAX))
        return false;
    out = static_cast<uint32_t>(value->num);
    return true;
}

static bool optionalBool(const Value& object, const char* key, bool& out,
                         bool defaultValue) {
    const Value* value = object.find(key);
    if (!value) { out = defaultValue; return true; }
    if (value->type != json::Type::Bool) return false;
    out = value->b;
    return true;
}

static const char* functionActionName(PjFunctionAction action) {
    return action == PjFunctionAction::Undefine ? "undefine" : "define";
}
static const char* functionModeName(PjFunctionMode mode) {
    switch (mode) {
        case PjFunctionMode::ARM: return "arm";
        case PjFunctionMode::Thumb: return "thumb";
        case PjFunctionMode::Unspecified: break;
    }
    return "";
}
static const char* dataKindName(PjDataKind kind) {
    switch (kind) {
        case PjDataKind::Code: return "code";
        case PjDataKind::Data: return "data";
        case PjDataKind::String: return "string";
        case PjDataKind::PointerTable: return "pointer_table";
        case PjDataKind::JumpTable: return "jump_table";
    }
    return "data";
}

static bool parseFunctionAction(const std::string& text, PjFunctionAction& out) {
    if (text == "define") { out = PjFunctionAction::Define; return true; }
    if (text == "undefine") { out = PjFunctionAction::Undefine; return true; }
    return false;
}
static bool parseFunctionMode(const std::string& text, PjFunctionMode& out) {
    if (text.empty()) { out = PjFunctionMode::Unspecified; return true; }
    if (text == "arm") { out = PjFunctionMode::ARM; return true; }
    if (text == "thumb") { out = PjFunctionMode::Thumb; return true; }
    return false;
}
static bool parseDataKind(const std::string& text, PjDataKind& out) {
    if (text == "code") { out = PjDataKind::Code; return true; }
    if (text == "data") { out = PjDataKind::Data; return true; }
    if (text == "string") { out = PjDataKind::String; return true; }
    if (text == "pointer_table") { out = PjDataKind::PointerTable; return true; }
    if (text == "jump_table") { out = PjDataKind::JumpTable; return true; }
    return false;
}

// ------------------------------------------------------------ serialize -----

static Value serializeTypeRegistry(const TypeRegistry& registry) {
    Value result = Value::Obj();
    result.set("version", Value::Int(1));
    auto fields = [](const std::vector<TypeField>& source) {
        Value array = Value::Arr();
        for (const auto& field : source) {
            Value item = Value::Obj();
            item.set("id", Value::Str(hexU64(field.id)));
            item.set("name", Value::Str(field.name));
            item.set("typeId", Value::Str(hexU64(field.typeId)));
            item.set("offsetBytes", Value::Str(hexU64(field.offsetBytes)));
            array.push(std::move(item));
        }
        return array;
    };
    Value definitions = Value::Arr();
    for (const auto& type : registry.types) {
        Value item = Value::Obj();
        item.set("id", Value::Str(hexU64(type.id)));
        item.set("name", Value::Str(type.name));
        item.set("kind", Value::Str(TypeKindName(type.kind)));
        item.set("sizeBytes", Value::Str(hexU64(type.sizeBytes)));
        item.set("signedValue", Value::Bool(type.signedValue));
        item.set("targetType", Value::Str(hexU64(type.targetType)));
        item.set("count", Value::Str(hexU64(type.count)));
        item.set("fields", fields(type.fields));
        item.set("parameters", fields(type.parameters));
        item.set("returnType", Value::Str(hexU64(type.returnType)));
        item.set("callingConvention", Value::Str(type.callingConvention));
        Value enumerators = Value::Arr();
        for (const auto& value : type.enumValues) {
            Value enumerator = Value::Obj();
            enumerator.set("name", Value::Str(value.name));
            enumerator.set("value", Value::Str(std::to_string(value.value)));
            enumerators.push(std::move(enumerator));
        }
        item.set("enumValues", std::move(enumerators));
        definitions.push(std::move(item));
    }
    result.set("types", std::move(definitions));
    Value applications = Value::Arr();
    for (const auto& application : registry.applications) {
        Value item = Value::Obj();
        item.set("address", Value::Str(hexU64(application.address)));
        item.set("typeId", Value::Str(hexU64(application.typeId)));
        item.set("name", Value::Str(application.name));
        applications.push(std::move(item));
    }
    result.set("applications", std::move(applications));
    return result;
}

static bool deserializeTypeRegistry(const Value& root, TypeRegistry& output) {
    const Value* version = root.find("version");
    const Value* definitions = root.find("types");
    const Value* applications = root.find("applications");
    if (!root.isObj() || !version || !version->isNum() || version->num != 1 ||
        !definitions || !definitions->isArr() || definitions->arr.size() > kMaxTypeDefinitions ||
        !applications || !applications->isArr() || applications->arr.size() > kMaxTypeApplications) return false;
    auto hex = [](const Value& value, const char* key, uint64_t& output) {
        return value.find(key) && optionalHexField(value, key, output);
    };
    auto name = [](const Value& value, const char* key, std::string& output) {
        return value.find(key) && optionalBoundedString(value, key, output, 96);
    };
    TypeRegistry registry;
    size_t totalMembers = 0;
    auto fields = [&](const Value& item, const char* key, std::vector<TypeField>& output) {
        const Value* array = item.find(key);
        if (!array || !array->isArr() || array->arr.size() > kMaxTypeMembers) return false;
        totalMembers += array->arr.size();
        if (totalMembers > kMaxTotalTypeMembers) return false;
        for (const auto& value : array->arr) {
            TypeField field;
            if (!value.isObj() || !hex(value, "id", field.id) || !name(value, "name", field.name) ||
                !hex(value, "typeId", field.typeId) || !hex(value, "offsetBytes", field.offsetBytes)) return false;
            output.push_back(std::move(field));
        }
        return true;
    };
    for (const auto& item : definitions->arr) {
        TypeDefinition type;
        std::string kind;
        if (!item.isObj() || !hex(item, "id", type.id) || !name(item, "name", type.name) || !name(item, "kind", kind) ||
            !hex(item, "sizeBytes", type.sizeBytes) || !item.find("signedValue") || !optionalBool(item, "signedValue", type.signedValue, false) ||
            !hex(item, "targetType", type.targetType) || !hex(item, "count", type.count) ||
            !fields(item, "fields", type.fields) || !fields(item, "parameters", type.parameters) ||
            !hex(item, "returnType", type.returnType) || !name(item, "callingConvention", type.callingConvention)) return false;
        bool kindFound = false;
        for (unsigned i = 0; i <= static_cast<unsigned>(TypeKind::Function); ++i)
            if (kind == TypeKindName(static_cast<TypeKind>(i))) { type.kind = static_cast<TypeKind>(i); kindFound = true; break; }
        if (!kindFound) return false;
        const Value* enumerators = item.find("enumValues");
        if (!enumerators || !enumerators->isArr() || enumerators->arr.size() > kMaxTypeMembers) return false;
        totalMembers += enumerators->arr.size();
        if (totalMembers > kMaxTotalTypeMembers) return false;
        for (const auto& value : enumerators->arr) {
            TypeEnumValue enumerator;
            const Value* number = value.find("value");
            if (!value.isObj() || !name(value, "name", enumerator.name) || !number || !number->isStr() ||
                number->str.empty() || number->str.size() > 20) return false;
            const auto parsed = std::from_chars(number->str.data(), number->str.data() + number->str.size(), enumerator.value);
            if (parsed.ec != std::errc{} || parsed.ptr != number->str.data() + number->str.size()) return false;
            type.enumValues.push_back(std::move(enumerator));
        }
        registry.types.push_back(std::move(type));
    }
    for (const auto& item : applications->arr) {
        TypeApplication application;
        if (!item.isObj() || !hex(item, "address", application.address) || !hex(item, "typeId", application.typeId) ||
            !name(item, "name", application.name)) return false;
        registry.applications.push_back(std::move(application));
    }
    if (!ValidateTypeRegistry(registry)) return false;
    output = std::move(registry);
    return true;
}

std::string SerializeProject(const ProjectState& st) {
    if (st.gmlBreakpoints.size() > kGmlMaxBreakpoints || st.gmlWatches.size() > kGmlMaxWatches)
        throw std::invalid_argument("GML project records exceed persistence limits");
    std::string typeError;
    if (!ValidateTypeRegistry(st.typeRegistry, &typeError))
        throw std::invalid_argument("Invalid type workbench: " + typeError);
    Value root = Value::Obj();
    root.set("version",        Value::Int(5));
    root.set("hash",           Value::Str(hexU64(st.hash)));
    root.set("binaryPath",     Value::Str(st.binaryPath));
    root.set("arch",           Value::Str(st.arch));
    root.set("engine",         Value::Str(st.engine));
    root.set("name",           Value::Str(st.name));
    root.set("status",         Value::Str(st.status));
    root.set("lastOpenedUnix", Value::Int(st.lastOpenedUnix));
    root.set("lastCursor",     Value::Str(hexU64(st.lastCursor)));
    root.set("lastCursorValid",Value::Bool(st.lastCursorValid));
    root.set("notes",          Value::Str(st.notes));
    if (!st.typeRegistry.empty()) root.set("typeRegistry", serializeTypeRegistry(st.typeRegistry));

    if (st.rawMappingSaved) {
        Value raw = Value::Obj();
        raw.set("base",          Value::Str(hexU64(st.rawImageBase)));
        raw.set("entry",         Value::Str(hexU64(st.rawEntry)));
        raw.set("entryExplicit", Value::Bool(st.rawEntryExplicit));
        raw.set("bigEndian",      Value::Bool(st.rawBigEndian));
        // Preserve the legacy Boolean for older v1-v3 readers while also
        // recording every DecoderFeatures mode.  Honor legacy in-memory callers
        // which still set only rawRiscvCompressed, and always emit the pair
        // consistently.
        uint32_t featureBits = st.rawDecoderFeatureBits;
        if (st.rawRiscvCompressed)
            featureBits |= kDecoderFeatureRiscvCompressed;
        else
            featureBits &= ~kDecoderFeatureRiscvCompressed;
        raw.set("featureBits",     Value::Int(featureBits));
        raw.set("riscvCompressed",Value::Bool(
            (featureBits & kDecoderFeatureRiscvCompressed) != 0));
        auto landmarks = st.rawLandmarks;
        std::sort(landmarks.begin(), landmarks.end(), [](const PjRawLandmark& a,
                                                         const PjRawLandmark& b) {
            if (a.address != b.address) return a.address < b.address;
            return a.name < b.name;
        });
        Value arr = Value::Arr();
        for (const PjRawLandmark& landmark : landmarks) {
            Value e = Value::Obj();
            e.set("address",  Value::Str(hexU64(landmark.address)));
            e.set("name",     Value::Str(landmark.name));
            e.set("evidence", Value::Str(landmark.evidence));
            arr.push(std::move(e));
        }
        raw.set("landmarks", std::move(arr));
        root.set("rawMapping", std::move(raw));
    }

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

    {   // Version 3: authoritative function decisions. Address order is stable,
        // unlike patches (whose vector order is semantic application order).
        auto overrides = st.functionOverrides;
        std::sort(overrides.begin(), overrides.end(), [](const auto& a, const auto& b) {
            return a.address < b.address;
        });
        Value arr = Value::Arr();
        for (const PjFunctionOverride& fn : overrides) {
            Value e = Value::Obj();
            e.set("a", Value::Str(hexU64(fn.address)));
            e.set("action", Value::Str(functionActionName(fn.action)));
            if (fn.action == PjFunctionAction::Define) {
                if (fn.exactExtentValid) e.set("size", Value::Str(hexU64(fn.exactSize)));
                if (fn.noreturn != PjOverrideBool::Unspecified)
                    e.set("noreturn", Value::Bool(fn.noreturn == PjOverrideBool::True));
                if (!fn.callingConvention.empty())
                    e.set("callingConvention", Value::Str(fn.callingConvention));
                if (!fn.prototype.empty()) e.set("prototype", Value::Str(fn.prototype));
                if (fn.mode != PjFunctionMode::Unspecified)
                    e.set("mode", Value::Str(functionModeName(fn.mode)));
            }
            arr.push(std::move(e));
        }
        root.set("functionOverrides", std::move(arr));
    }
    {   // Version 3: authoritative, non-overlapping code/data spans.
        auto overrides = st.dataOverrides;
        std::sort(overrides.begin(), overrides.end(), [](const auto& a, const auto& b) {
            return a.address < b.address;
        });
        Value arr = Value::Arr();
        for (const PjDataOverride& span : overrides) {
            Value e = Value::Obj();
            e.set("a", Value::Str(hexU64(span.address)));
            e.set("size", Value::Str(hexU64(span.size)));
            e.set("kind", Value::Str(dataKindName(span.kind)));
            if (!span.type.empty()) e.set("type", Value::Str(span.type));
            arr.push(std::move(e));
        }
        root.set("dataOverrides", std::move(arr));
    }

    if (st.listingLayoutSaved) {
        // Linear-listing visibility/fold state. Section identity is the stable
        // (RVA,name) pair; sort it for deterministic, reviewable sidecars.
        Value layout = Value::Obj();
        layout.set("peHeaderVisible", Value::Bool(st.peHeaderVisible));
        layout.set("peHeaderFolded",  Value::Bool(st.peHeaderFolded));
        auto sections = st.listingSections;
        std::sort(sections.begin(), sections.end(), [](const PjSectionView& a, const PjSectionView& b) {
            if (a.rva != b.rva) return a.rva < b.rva;
            return a.name < b.name;
        });
        Value arr = Value::Arr();
        for (const auto& s : sections) {
            Value e = Value::Obj();
            e.set("rva",     Value::Str(hexU64(s.rva)));
            e.set("name",    Value::Str(s.name));
            e.set("visible", Value::Bool(s.visible));
            e.set("folded",  Value::Bool(s.folded));
            arr.push(std::move(e));
        }
        layout.set("sections", std::move(arr));
        root.set("listingLayout", std::move(layout));
    }

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
            if (st.bpDisabled.contains(a)) e.set("enabled", Value::Bool(false));
            arr.push(std::move(e));
        }
        root.set("breakpoints", std::move(arr));
    }
    {
        // Version 4 named experiments. Vector order is presentation order;
        // stable ids, never indices or names, own patch membership.
        Value arr = Value::Arr();
        for (const PjPatchSet& set : st.patchSets) {
            Value e = Value::Obj();
            e.set("id", Value::Str(hexU64(set.id)));
            e.set("name", Value::Str(set.name));
            e.set("enabled", Value::Bool(set.enabled));
            arr.push(std::move(e));
        }
        root.set("patchSets", std::move(arr));
    }
    {
        Value arr = Value::Arr();
        // Patch order is application order, not presentation order. Overlapping
        // patches resolve later-wins in the in-memory image and Save Binary As;
        // serializing a sorted copy silently changes that result after reopening.
        for (const auto& p : patchesForPersistence(st.patches)) {
            Value e = Value::Obj();
            e.set("a",     Value::Str(hexU64(p.address)));
            e.set("orig",  Value::Str(bytesToHex(p.orig)));
            e.set("bytes", Value::Str(bytesToHex(p.bytes)));
            e.set("set",   Value::Str(hexU64(p.patchSetId)));
            arr.push(std::move(e));
        }
        root.set("patches", std::move(arr));
    }
    {
        Value arr = Value::Arr();
        for (auto& w : st.watches) { Value e = Value::Obj(); e.set("v", Value::Str(w)); arr.push(std::move(e)); }
        root.set("watches", std::move(arr));
    }
    {
        Value arr = Value::Arr();
        for (const auto& breakpoint : st.gmlBreakpoints) {
            Value entry = Value::Obj();
            entry.set("archiveHash", Value::Str(hexU64(breakpoint.location.archiveHash)));
            entry.set("codeIndex", Value::Int(breakpoint.location.codeIndex));
            entry.set("byteOffset", Value::Int(breakpoint.location.byteOffset));
            entry.set("parentCodeIndex", Value::Int(breakpoint.location.parentCodeIndex));
            entry.set("reserved", Value::Int(breakpoint.location.reserved));
            entry.set("enabled", Value::Bool(breakpoint.enabled));
            arr.push(std::move(entry));
        }
        root.set("gmlBreakpoints", std::move(arr));
    }
    {
        Value arr = Value::Arr();
        for (const auto& watch : st.gmlWatches) {
            // An accidentally supplied transient watch must fail the mandatory
            // reader round trip, never silently serialize a runtime pointer/id.
            if (!GmlVariableTargetPersistent(watch.target))
                throw std::invalid_argument("GML watch is not a persistent symbolic target");
            Value entry = Value::Obj();
            entry.set("archiveHash", Value::Str(hexU64(watch.target.archiveHash)));
            entry.set("scope", Value::Str(watch.target.scope == GmlVariableScope::Global ? "global" : "unique_object"));
            entry.set("objectIndex", Value::Int(watch.target.objectIndex));
            entry.set("variable", Value::Str(watch.target.variableName));
            entry.set("label", Value::Str(watch.label));
            arr.push(std::move(entry));
        }
        root.set("gmlWatches", std::move(arr));
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

static bool DeserializeProjectImpl(const std::string& text, ProjectState& out) {
    Value root;
    if (!json::Parse(text, root, kProjectJsonLimits) || !root.isObj()) return false;
    int version = 1; // pre-versioned development sidecars use the v1 schema.
    if (const Value* value = root.find("version")) {
        if (!value->isNum() || !std::isfinite(value->num) ||
            value->num != std::floor(value->num) || value->num < 1.0 || value->num > 5.0)
            return false;
        version = static_cast<int>(value->num);
    }
    ProjectState st;
    if (const Value* types = root.find("typeRegistry"); types && !deserializeTypeRegistry(*types, st.typeRegistry)) return false;
    if (!optionalHexField(root, "hash", st.hash) ||
        !optionalHexField(root, "lastCursor", st.lastCursor) ||
        !optionalBoundedString(root, "binaryPath", st.binaryPath, 32u * 1024u) ||
        !optionalBoundedString(root, "arch", st.arch, 64) ||
        !optionalBoundedString(root, "engine", st.engine, 64) ||
        !optionalBoundedString(root, "name", st.name, 4096) ||
        !optionalBoundedString(root, "status", st.status, 64, "analyzed") ||
        !optionalBoundedString(root, "notes", st.notes, kProjectJsonStringTokenBytes) ||
        !optionalInt64(root, "lastOpenedUnix", st.lastOpenedUnix))
        return false;
    // Old sidecars had no explicit flag; preserve their non-zero cursor while
    // allowing new sidecars to distinguish a real VA 0 from "not saved".
    if (!optionalBool(root, "lastCursorValid", st.lastCursorValid,
                      st.lastCursor != 0))
        return false;

    if (const Value* raw = root.find("rawMapping")) {
        if (!raw->isObj()) return false;
        // A raw mapping is the coordinate system for every persisted address.
        // Do not let malformed/overflowing/trailing-junk hex silently collapse
        // to a plausible VA 0 and shift annotations onto the fallback mapping.
        const Value* baseValue = raw->find("base");
        const Value* entryValue = raw->find("entry");
        if (!baseValue || !entryValue || !baseValue->isStr() || !entryValue->isStr() ||
            !tryParseU64(baseValue->str, st.rawImageBase) ||
            !tryParseU64(entryValue->str, st.rawEntry))
            return false;
        st.rawMappingSaved  = true;
        const bool hasLegacyRvc = raw->find("riscvCompressed") != nullptr;
        const bool hasFeatureBits = raw->find("featureBits") != nullptr;
        if (!optionalBool(*raw, "entryExplicit", st.rawEntryExplicit, false) ||
            !optionalBool(*raw, "bigEndian", st.rawBigEndian, false) ||
            !optionalBool(*raw, "riscvCompressed", st.rawRiscvCompressed, true))
            return false;
        uint32_t featureBits = st.rawRiscvCompressed
                             ? kDecoderFeatureRiscvCompressed : 0u;
        if (hasFeatureBits &&
            !optionalU32(*raw, "featureBits", featureBits,
                         kDecoderFeatureRiscvCompressed))
            return false;
        DecoderFeatures decodedFeatures;
        if (!DecoderFeaturesFromBits(featureBits, decodedFeatures) ||
            (hasFeatureBits && hasLegacyRvc &&
             decodedFeatures.riscvCompressed != st.rawRiscvCompressed))
            return false;
        st.rawDecoderFeatureBits = featureBits;
        st.rawRiscvCompressed = decodedFeatures.riscvCompressed;
        if (const Value* a = raw->find("landmarks"); a && !a->isArr()) return false;
        if (const Value* a = raw->find("landmarks"); a && a->isArr()) {
            constexpr size_t kMaxRawLandmarks = 4096; // matches BinaryFile::kMaxAnalysisLandmarks
            // Bound the persisted collection itself, not merely the number of
            // unique records retained below.  Otherwise a hostile array of
            // duplicate landmarks can evade the cap and repeatedly scan the
            // growing deduplication vector.
            if (a->arr.size() > kMaxRawLandmarks) return false;
            for (const Value& e : a->arr) {
                if (!e.isObj()) return false;
                PjRawLandmark landmark;
                const Value* addressValue = e.find("address");
                if (!addressValue || !addressValue->isStr() ||
                    !tryParseU64(addressValue->str, landmark.address))
                    return false;
                if (!optionalBoundedString(e, "name", landmark.name, 256) || !e.find("name") ||
                    !optionalBoundedString(e, "evidence", landmark.evidence, 4096))
                    return false;
                if (landmark.name.empty()) continue;
                const bool duplicate = std::any_of(st.rawLandmarks.begin(), st.rawLandmarks.end(),
                    [&](const PjRawLandmark& old) {
                        return old.address == landmark.address && old.name == landmark.name;
                    });
                if (!duplicate) st.rawLandmarks.push_back(std::move(landmark));
            }
        }
    }

    auto loadMap = [&](const char* key, std::unordered_map<uint64_t, std::string>& m,
                       size_t maxValueBytes) {
        constexpr size_t kMaxMapEntries = 65'536;
        const Value* a = root.find(key);
        if (!a) return true;
        if (!a->isArr() || a->arr.size() > kMaxMapEntries) return false;
        for (const Value& e : a->arr) {
            if (!e.isObj()) return false;
            uint64_t address = 0;
            std::string value;
            if (!optionalHexField(e, "a", address) || !e.find("a") ||
                !optionalBoundedString(e, "v", value, maxValueBytes) || !e.find("v") ||
                !m.emplace(address, std::move(value)).second)
                return false;
        }
        return true;
    };
    if (!loadMap("names", st.names, 4096) ||
        !loadMap("comments", st.comments, 64u * 1024u) ||
        !loadMap("algorithmLabels", st.algorithmLabels, 4096))
        return false;

    // Version-3 analyst overrides are optional so v1/v2 migrate to empty/default
    // vectors. When present, parse strictly: these values supersede heuristics and
    // therefore must never be silently repaired into a different analyst decision.
    if (const Value* a = root.find("functionOverrides")) {
        constexpr size_t kMaxFunctionOverrides = 65536;
        constexpr size_t kMaxConvention = 64;
        constexpr size_t kMaxPrototype = 4096;
        if (!a->isArr() || a->arr.size() > kMaxFunctionOverrides) return false;
        for (const Value& e : a->arr) {
            if (!e.isObj()) return false;
            const Value* av = e.find("a");
            const Value* action = e.find("action");
            PjFunctionOverride fn;
            if (!av || !av->isStr() || !tryParseU64(av->str, fn.address) ||
                !action || !action->isStr() || !parseFunctionAction(action->str, fn.action))
                return false;
            if (std::any_of(st.functionOverrides.begin(), st.functionOverrides.end(),
                            [&](const auto& old) { return old.address == fn.address; }))
                return false;

            if (const Value* size = e.find("size")) {
                if (fn.action != PjFunctionAction::Define || !size->isStr() ||
                    !tryParseU64(size->str, fn.exactSize) || !fn.exactSize ||
                    fn.exactSize > UINT32_MAX || fn.address > UINT64_MAX - fn.exactSize)
                    return false;
                fn.exactExtentValid = true;
            }
            if (const Value* noreturn = e.find("noreturn")) {
                if (fn.action != PjFunctionAction::Define ||
                    noreturn->type != json::Type::Bool) return false;
                fn.noreturn = noreturn->b ? PjOverrideBool::True : PjOverrideBool::False;
            }
            if (const Value* convention = e.find("callingConvention")) {
                if (fn.action != PjFunctionAction::Define || !convention->isStr() ||
                    convention->str.size() > kMaxConvention) return false;
                fn.callingConvention = convention->str;
            }
            if (const Value* prototype = e.find("prototype")) {
                if (fn.action != PjFunctionAction::Define || !prototype->isStr() ||
                    prototype->str.size() > kMaxPrototype) return false;
                fn.prototype = prototype->str;
            }
            if (const Value* mode = e.find("mode")) {
                if (fn.action != PjFunctionAction::Define || !mode->isStr() ||
                    !parseFunctionMode(mode->str, fn.mode) ||
                    fn.mode == PjFunctionMode::Unspecified) return false;
            }
            st.functionOverrides.push_back(std::move(fn));
        }
        std::sort(st.functionOverrides.begin(), st.functionOverrides.end(),
                  [](const auto& x, const auto& y) { return x.address < y.address; });
    }

    if (const Value* a = root.find("dataOverrides")) {
        constexpr size_t kMaxDataOverrides = 65536;
        constexpr uint64_t kMaxOverrideSpan = 1ull << 30; // one analyst record, 1 GiB
        constexpr size_t kMaxType = 4096;
        if (!a->isArr() || a->arr.size() > kMaxDataOverrides) return false;
        for (const Value& e : a->arr) {
            if (!e.isObj()) return false;
            const Value* av = e.find("a");
            const Value* size = e.find("size");
            const Value* kind = e.find("kind");
            PjDataOverride span;
            if (!av || !av->isStr() || !tryParseU64(av->str, span.address) ||
                !size || !size->isStr() || !tryParseU64(size->str, span.size) ||
                !span.size || span.size > kMaxOverrideSpan ||
                span.address > UINT64_MAX - span.size ||
                !kind || !kind->isStr() || !parseDataKind(kind->str, span.kind))
                return false;
            if (const Value* type = e.find("type")) {
                if (!type->isStr() || type->str.size() > kMaxType) return false;
                span.type = type->str;
            }
            st.dataOverrides.push_back(std::move(span));
        }
        std::sort(st.dataOverrides.begin(), st.dataOverrides.end(),
                  [](const auto& x, const auto& y) { return x.address < y.address; });
        for (size_t i = 1; i < st.dataOverrides.size(); ++i) {
            const PjDataOverride& before = st.dataOverrides[i - 1];
            if (st.dataOverrides[i].address < before.address + before.size) return false;
        }
    }

    (void)version; // documents the accepted migration range above.

    if (const Value* layout = root.find("listingLayout")) {
        if (!layout->isObj()) return false;
        st.listingLayoutSaved = true;
        if (!optionalBool(*layout, "peHeaderVisible", st.peHeaderVisible, false) ||
            !optionalBool(*layout, "peHeaderFolded", st.peHeaderFolded, true))
            return false;
        if (const Value* a = layout->find("sections")) {
            constexpr size_t kMaxPersistedSections = 4096;
            if (!a->isArr() || a->arr.size() > kMaxPersistedSections) return false;
            for (const auto& e : a->arr) {
                if (!e.isObj()) return false;
                PjSectionView v;
                if (!optionalHexField(e, "rva", v.rva) || !e.find("rva") ||
                    !optionalBoundedString(e, "name", v.name, 256) || !e.find("name"))
                    return false;
                if (!optionalBool(e, "visible", v.visible, false) ||
                    !optionalBool(e, "folded", v.folded, true))
                    return false;
                const bool duplicate = std::any_of(st.listingSections.begin(), st.listingSections.end(),
                    [&](const PjSectionView& old) { return old.rva == v.rva && old.name == v.name; });
                if (duplicate) return false;
                st.listingSections.push_back(std::move(v));
            }
        }
    }

    if (const Value* a = root.find("labels")) {
        constexpr size_t kMaxLabels = 65'536;
        if (!a->isArr() || a->arr.size() > kMaxLabels) return false;
        for (const auto& e : a->arr) {
            if (!e.isObj()) return false;
            PjLabel l;
            if (!optionalBoundedString(e, "kind", l.targetKind, 64) ||
                !optionalBoundedString(e, "target", l.target, 4096) ||
                !optionalBoundedString(e, "label", l.label, 4096) ||
                !optionalBoundedString(e, "note", l.note, 64u * 1024u))
                return false;
            l.confidence = 1.0f;
            if (const Value* cv = e.find("confidence")) {
                if (!cv->isNum() || !std::isfinite(cv->num)) return false;
                l.confidence = static_cast<float>(cv->num);
            }
            if (!std::isfinite(l.confidence)) return false;
            if (l.confidence < 0.0f) l.confidence = 0.0f;
            if (l.confidence > 1.0f) l.confidence = 1.0f;
            if (!l.targetKind.empty() && !l.target.empty() && !l.label.empty())
                st.labels.push_back(std::move(l));
        }
    }

    if (const Value* c = root.find("connection")) {
        if (!c->isObj()) return false;
        if (!optionalBool(*c, "enabled", st.connection.enabled, false) ||
            !optionalBool(*c, "localhostOnly", st.connection.localhostOnly, true) ||
            !optionalBool(*c, "authEnabled", st.connection.authEnabled, false) ||
            !optionalBoundedString(*c, "accessToken", st.connection.accessToken, 256))
            return false;
        std::string ignored;
        if (!ValidateConnectionConfig(st.connection, &ignored)) return false;
    }
    if (const Value* a = root.find("connectionEvents")) {
        constexpr size_t kMaxConnectionEvents = 8192;
        if (!a->isArr() || a->arr.size() > kMaxConnectionEvents) return false;
        for (const auto& e : a->arr) {
            ConnectionEnvelope ev;
            std::string ignored;
            if (!ConnectionEnvelopeFromJsonValue(e, ev, &ignored)) return false;
            st.connectionEvents.push_back(std::move(ev));
        }
    }

    if (const Value* a = root.find("bookmarks")) {
        constexpr size_t kMaxBookmarks = 65'536;
        if (!a->isArr() || a->arr.size() > kMaxBookmarks) return false;
        for (const Value& e : a->arr) {
            if (!e.isObj()) return false;
            PjBookmark bookmark;
            if (!optionalHexField(e, "a", bookmark.address) || !e.find("a") ||
                !optionalBoundedString(e, "label", bookmark.label, 4096))
                return false;
            st.bookmarks.push_back(std::move(bookmark));
        }
    }

    if (const Value* a = root.find("breakpoints")) {
        constexpr size_t kMaxBreakpoints = 65'536;
        if (!a->isArr() || a->arr.size() > kMaxBreakpoints) return false;
        for (const auto& e : a->arr) {
            if (!e.isObj()) return false;
            uint64_t addr = 0;
            std::string condition;
            bool enabled = true;
            if (!optionalHexField(e, "a", addr) || !e.find("a") ||
                !optionalBoundedString(e, "cond", condition, 4096) ||
                !optionalBool(e, "enabled", enabled, true))
                return false;
            // Keep the breakpoints vector and the bpConditions map 1:1 — a duplicate
            // address would otherwise break that implicit invariant.
            if (std::find(st.breakpoints.begin(), st.breakpoints.end(), addr) != st.breakpoints.end())
                return false;
            st.breakpoints.push_back(addr);
            if (!enabled) st.bpDisabled.insert(addr);
            if (!condition.empty()) st.bpConditions[addr] = std::move(condition);
            if (const Value* everyN = e.find("everyN")) {
                if (!everyN->isNum() || !std::isfinite(everyN->num) ||
                    everyN->num != std::floor(everyN->num) || everyN->num < 0 ||
                    everyN->num > 0x7FFFFFFF) return false;
                const uint32_t n = static_cast<uint32_t>(everyN->num);
                if (n > 1) st.bpEveryN[addr] = n;
            }
        }
    }

    if (const Value* a = root.find("gmlBreakpoints")) {
        if (version < 5 || !a->isArr() || a->arr.size() > kGmlMaxBreakpoints) return false;
        for (const auto& entry : a->arr) {
            if (!entry.isObj()) return false;
            GmlSavedBreakpoint breakpoint;
            if (!entry.find("archiveHash") || !entry.find("codeIndex") || !entry.find("byteOffset") ||
                !optionalHexField(entry, "archiveHash", breakpoint.location.archiveHash) ||
                !optionalU32(entry, "codeIndex", breakpoint.location.codeIndex) ||
                !optionalU32(entry, "byteOffset", breakpoint.location.byteOffset) ||
                !optionalU32(entry, "parentCodeIndex", breakpoint.location.parentCodeIndex, kGmlNoCodeIndex) ||
                !optionalU32(entry, "reserved", breakpoint.location.reserved) ||
                !optionalBool(entry, "enabled", breakpoint.enabled, true) ||
                !GmlLocationHasIdentity(breakpoint.location)) return false;
            for (const auto& previous : st.gmlBreakpoints)
                if (previous.location == breakpoint.location) return false;
            st.gmlBreakpoints.push_back(breakpoint);
        }
    }
    if (const Value* a = root.find("gmlWatches")) {
        if (version < 5 || !a->isArr() || a->arr.size() > kGmlMaxWatches) return false;
        for (const auto& entry : a->arr) {
            if (!entry.isObj()) return false;
            GmlSavedWatch watch;
            std::string scope;
            if (!entry.find("archiveHash") || !entry.find("scope") || !entry.find("variable") ||
                !optionalHexField(entry, "archiveHash", watch.target.archiveHash) ||
                !optionalBoundedString(entry, "scope", scope, 32) ||
                !optionalU32(entry, "objectIndex", watch.target.objectIndex, kGmlNoCodeIndex) ||
                !optionalBoundedString(entry, "variable", watch.target.variableName, kGmlMaxVariableNameBytes) ||
                !optionalBoundedString(entry, "label", watch.label, 4096)) return false;
            if (scope == "global") watch.target.scope = GmlVariableScope::Global;
            else if (scope == "unique_object") watch.target.scope = GmlVariableScope::UniqueObject;
            else return false;
            // Reject known transient authority even if another writer tried to
            // sneak it into an otherwise symbolic v5 watch.
            for (const char* forbidden : { "address", "instanceId", "frameId", "owner", "armed", "freezeActive" })
                if (entry.find(forbidden)) return false;
            if (!GmlVariableTargetPersistent(watch.target)) return false;
            st.gmlWatches.push_back(std::move(watch));
        }
    }
    if (const Value* a = root.find("patchSets")) {
        if (version < 4 || !a->isArr() ||
            a->arr.size() > kMaxNamedPatchSets)
            return false;
        for (const Value& e : a->arr) {
            if (!e.isObj()) return false;
            PjPatchSet set;
            const Value* id = e.find("id");
            const Value* name = e.find("name");
            if (!id || !id->isStr() || !tryParseU64(id->str, set.id) ||
                !name || !name->isStr() ||
                name->str.size() > kMaxPatchSetNameBytes ||
                !optionalBool(e, "enabled", set.enabled, true))
                return false;
            set.name = name->str;
            st.patchSets.push_back(std::move(set));
        }
    }

    if (const Value* a = root.find("patches")) {
        if (!a->isArr() || a->arr.size() > kMaxPatches) return false;
        size_t totalPatchBytes = 0;
        for (const auto& e : a->arr) {
            if (!e.isObj()) return false;
            PjPatch p;
            const Value* orig = e.find("orig");
            const Value* bytes = e.find("bytes");
            if (!optionalHexField(e, "a", p.address) || !e.find("a") ||
                !orig || !orig->isStr() || !bytes || !bytes->isStr() ||
                !hexToBytes(orig->str, p.orig, kMaxPatchBytes) ||
                !hexToBytes(bytes->str, p.bytes, kMaxPatchBytes))
                return false;
            if (version >= 4 &&
                (!optionalHexField(e, "set", p.patchSetId) || !e.find("set")))
                return false;
            // Validate before the file splicer trusts these: non-empty, orig and patch
            // the same length, and a sane size cap (a corrupt sidecar mustn't drive a
            // huge / mismatched write into the binary).
            if (p.bytes.empty() || p.bytes.size() != p.orig.size() ||
                p.address > UINT64_MAX - p.bytes.size() ||
                p.bytes.size() > kMaxTotalPatchBytes -
                    std::min(totalPatchBytes, kMaxTotalPatchBytes))
                return false;
            totalPatchBytes += p.bytes.size();
            st.patches.push_back(std::move(p));
        }
    }
    if (!BuildPatchSetPlan(st.patches, st.patchSets).success) return false;

    if (const Value* a = root.find("watches")) {
        constexpr size_t kMaxWatches = 4096;
        if (!a->isArr() || a->arr.size() > kMaxWatches) return false;
        for (const auto& e : a->arr) {
            if (!e.isObj()) return false;
            std::string watch;
            if (!optionalBoundedString(e, "v", watch, 4096) || !e.find("v")) return false;
            if (!watch.empty()) st.watches.push_back(std::move(watch));
        }
    }

    if (const Value* a = root.find("syntheses")) {
        constexpr size_t kMaxSyntheses = 4096;
        if (!a->isArr() || a->arr.size() > kMaxSyntheses) return false;
        for (const auto& e : a->arr) {
            if (!e.isObj()) return false;
            PjSynthesis s;
            if (!optionalHexField(e, "a", s.address) || !e.find("a") ||
                !optionalBoundedString(e, "pseudoC", s.pseudoC, 1u << 20) ||
                !optionalBoundedString(e, "why", s.reasoning, 1u << 20))
                return false;
            if (!optionalU32(e, "size", s.size) ||
                !optionalU32(e, "sp", s.samplesPassed) ||
                !optionalU32(e, "st", s.samplesTotal))
                return false;
            if (!optionalBool(e, "z3", s.z3Equivalent, false)) return false;
            st.syntheses.push_back(std::move(s));
        }
    }

    if (const Value* a = root.find("hotPatches")) {
        constexpr size_t kMaxHotPatches = 4096;
        if (!a->isArr() || a->arr.size() > kMaxHotPatches) return false;
        for (const auto& e : a->arr) {
            if (!e.isObj()) return false;
            PjHotPatch h;
            if (!optionalHexField(e, "a", h.address) || !e.find("a") ||
                !optionalBoundedString(e, "lang", h.lang, 64) ||
                !optionalBoundedString(e, "src", h.source, 1u << 20) || !e.find("src"))
                return false;
            if (!h.source.empty()) st.hotPatches.push_back(std::move(h));
        }
    }

    out = std::move(st);
    return true;
}

bool DeserializeProject(const std::string& text, ProjectState& out) {
    try {
        return DeserializeProjectImpl(text, out);
    } catch (const std::bad_alloc&) {
        return false;
    } catch (const std::length_error&) {
        return false;
    }
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

ProjectLoadResult LoadProjectDetailed(uint64_t hash, ProjectState& out) {
    std::lock_guard<std::recursive_mutex> lock(gProjectStoreMutex);
    ProjectLoadResult result;
    try {
    if (!hash) {
        result.error = "project hash is zero";
        return result;
    }
    const fs::path path = ProjectPathForHash(hash);
    auto loadCandidate = [&](const fs::path& candidatePath, ProjectLoadAttempt& outcome,
                             ProjectState& candidate) {
        std::error_code existenceError;
        const bool exists = fs::exists(candidatePath, existenceError);
        if (existenceError) {
            outcome = ProjectLoadAttempt::Unavailable;
            return;
        }
        if (!exists) {
            outcome = ProjectLoadAttempt::Missing;
            return;
        }
        std::string text;
        if (!atomic_file::Read(candidatePath, text, kMaxProjectSidecarBytes)) {
            outcome = ProjectLoadAttempt::Unavailable;
            return;
        }
        if (!DeserializeProject(text, candidate)) {
            outcome = ProjectLoadAttempt::Malformed;
            return;
        }
        if (candidate.hash != hash) {
            outcome = ProjectLoadAttempt::IdentityMismatch;
            return;
        }
        outcome = ProjectLoadAttempt::Loaded;
    };

    ProjectState candidate;
    loadCandidate(path, result.primary, candidate);
    if (result.primary == ProjectLoadAttempt::Loaded) {
        out = std::move(candidate);
        result.loaded = true;
        result.source = ProjectLoadSource::Primary;
        return result;
    }

    candidate = {};
    loadCandidate(atomic_file::BackupPath(path), result.backup, candidate);
    if (result.backup == ProjectLoadAttempt::Loaded) {
        out = std::move(candidate);
        result.loaded = true;
        result.source = ProjectLoadSource::Backup;
        result.error = result.primary == ProjectLoadAttempt::Malformed
                     ? "primary project sidecar was malformed; recovered the backup"
                     : result.primary == ProjectLoadAttempt::IdentityMismatch
                     ? "primary project sidecar had the wrong content hash; recovered the backup"
                     : "primary project sidecar was unavailable; recovered the backup";
        return result;
    }

    auto attemptName = [](ProjectLoadAttempt attempt) {
        switch (attempt) {
            case ProjectLoadAttempt::Missing: return "missing";
            case ProjectLoadAttempt::Unavailable: return "unavailable";
            case ProjectLoadAttempt::Malformed: return "malformed";
            case ProjectLoadAttempt::IdentityMismatch: return "content-hash mismatch";
            case ProjectLoadAttempt::Loaded: return "loaded";
            default: return "not tried";
        }
    };
    result.error = std::string("project sidecar is ") + attemptName(result.primary) +
                   "; backup is " + attemptName(result.backup);
    return result;
    } catch (const std::bad_alloc&) {
        // Preserve `out` and collapse resource exhaustion into the same normal,
        // structured unavailable outcome as a bounded read failure. Do not try
        // to allocate a diagnostic string while the allocator is exhausted.
        if (result.primary == ProjectLoadAttempt::NotTried)
            result.primary = ProjectLoadAttempt::Unavailable;
        else if (result.backup == ProjectLoadAttempt::NotTried)
            result.backup = ProjectLoadAttempt::Unavailable;
        else if (!ProjectLoadAttemptRequiresWarning(result.primary) &&
                 !ProjectLoadAttemptRequiresWarning(result.backup))
            result.backup = ProjectLoadAttempt::Unavailable;
        result.loaded = false;
        result.source = ProjectLoadSource::None;
        result.error.clear();
        return result;
    } catch (const std::length_error&) {
        if (result.primary == ProjectLoadAttempt::NotTried)
            result.primary = ProjectLoadAttempt::Unavailable;
        else if (result.backup == ProjectLoadAttempt::NotTried)
            result.backup = ProjectLoadAttempt::Unavailable;
        else if (!ProjectLoadAttemptRequiresWarning(result.primary) &&
                 !ProjectLoadAttemptRequiresWarning(result.backup))
            result.backup = ProjectLoadAttempt::Unavailable;
        result.loaded = false;
        result.source = ProjectLoadSource::None;
        result.error.clear();
        return result;
    }
}

bool LoadProject(uint64_t hash, ProjectState& out) {
    return LoadProjectDetailed(hash, out).loaded;
}

static bool parseRecents(const std::string& text, std::vector<RecentEntry>& recents) {
    static constexpr json::JsonParseLimits kRecentsJsonLimits{
        16, 4096, 4u * 1024u * 1024u, 256, 32u * 1024u, 128
    };
    try {
        Value root;
        if (!json::Parse(text, root, kRecentsJsonLimits)) return false;
        const Value* arr = root.isArr() ? &root : root.find("projects");
        if (!arr || !arr->isArr() || arr->arr.size() > 256) return false;
        std::vector<RecentEntry> parsed;
        parsed.reserve(arr->arr.size());
        std::unordered_set<uint64_t> seen;
        for (const auto& e : arr->arr) {
            if (!e.isObj()) return false;
            RecentEntry r;
            if (!optionalHexField(e, "hash", r.hash) || !e.find("hash") || !r.hash ||
                !optionalBoundedString(e, "path", r.path, 32u * 1024u) ||
                !optionalBoundedString(e, "name", r.name, 4096) ||
                !optionalBoundedString(e, "arch", r.arch, 64) ||
                !optionalBoundedString(e, "status", r.status, 64, "analyzed") ||
                !optionalInt64(e, "lastOpenedUnix", r.lastOpenedUnix) ||
                !seen.insert(r.hash).second)
                return false;
            parsed.push_back(std::move(r));
        }
        recents = std::move(parsed);
        return true;
    } catch (const std::bad_alloc&) {
        return false;
    } catch (const std::length_error&) {
        return false;
    }
}

std::vector<RecentEntry> LoadRecents() {
    std::lock_guard<std::recursive_mutex> lock(gProjectStoreMutex);
    std::vector<RecentEntry> recents;
    const fs::path path = recentsPath();
    std::string text;
    if (atomic_file::Read(path, text, kMaxRecentsBytes) &&
        parseRecents(text, recents))
        return recents;
    recents.clear();
    text.clear();
    if (atomic_file::Read(atomic_file::BackupPath(path), text,
                          kMaxRecentsBytes))
        parseRecents(text, recents);
    return recents;
}

static bool writeRecents(const std::vector<RecentEntry>& recents) {
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
    const std::string text = json::Dump(root, true);
    std::vector<RecentEntry> checked;
    if (text.size() > kMaxRecentsBytes || !parseRecents(text, checked)) return false;
    return atomic_file::Write(recentsPath(), text);
}

static bool upsertRecent(const ProjectState& st) {
    auto recents = LoadRecents();
    recents.erase(std::remove_if(recents.begin(), recents.end(),
                                 [&](const RecentEntry& r){ return r.hash == st.hash; }), recents.end());
    RecentEntry r;
    r.hash = st.hash; r.path = st.binaryPath; r.arch = st.arch; r.status = st.status;
    r.name = st.name.empty() ? st.binaryPath : st.name;
    r.lastOpenedUnix = st.lastOpenedUnix;
    recents.insert(recents.begin(), std::move(r));   // most-recent first
    if (recents.size() > 50) recents.resize(50);
    return writeRecents(recents);
}

static bool buildValidatedProjectSidecar(const ProjectState& st,
                                         std::string& text) {
    if (!patchStateFitsPersistenceBudget(st.patches, st.patchSets)) return false;
    text = SerializeProject(st);
    if (text.size() > kMaxProjectSidecarBytes) return false;

    ProjectState checked;
    if (!DeserializeProject(text, checked) || checked.hash != st.hash) return false;
    // The serializer is deterministic.  Requiring a canonical fixed point makes
    // the validation a true read/write round trip and catches any future field
    // whose reader silently drops a writer representation.
    return SerializeProject(checked) == text;
}

ProjectSaveResult SaveProjectDetailed(const ProjectState& st) {
    std::lock_guard<std::recursive_mutex> lock(gProjectStoreMutex);
    ProjectSaveResult result;
    if (!st.hash) {
        result.error = "project hash is zero";
        return result;
    }
    // Don't litter %APPDATA% with a sidecar that holds no analysis (just an
    // auto-stamped open time). Still record the open in the recents index so the
    // Projects tab tracks recently-opened binaries; a later save with real
    // annotations writes the sidecar. Existing projects must also persist an
    // empty state: leaving their old sidecar untouched would resurrect the last
    // annotation or patch after it was removed. Include backup-only projects so
    // recovery followed by clearing content obeys the same rule.
    try {
        const fs::path path = ProjectPathForHash(st.hash);
        const bool writeSidecar = st.hasContent() || fs::exists(path) ||
                                  fs::exists(atomic_file::BackupPath(path));
        if (writeSidecar) {
            std::string text;
            if (!buildValidatedProjectSidecar(st, text)) {
                result.error = "project state exceeds persistence limits or does not round-trip";
                return result;
            }
            if (!atomic_file::Write(path, text)) {
                result.error = "project sidecar commit failed";
                return result;
            }
            result.sidecarWritten = true;
        }
        result.saved = true;
    } catch (const std::bad_alloc&) {
        result.error = "project serialization exhausted memory";
        return result;
    } catch (const std::length_error&) {
        result.error = "project serialization exceeded container limits";
        return result;
    } catch (const std::exception&) {
        result.error = "project sidecar commit failed";
        return result;
    }

    result.recentsAttempted = true;
    try {
        result.recentsUpdated = upsertRecent(st);
    } catch (const std::bad_alloc&) {
        result.recentsUpdated = false;
    } catch (const std::length_error&) {
        result.recentsUpdated = false;
    } catch (...) {
        result.recentsUpdated = false;
    }
    if (!result.recentsUpdated)
        result.warning = "project was saved, but the recents index could not be updated";
    return result;
}

bool SaveProject(const ProjectState& st) {
    return SaveProjectDetailed(st).saved;
}

bool RemoveRecent(uint64_t hash) {
    std::lock_guard<std::recursive_mutex> lock(gProjectStoreMutex);
    auto recents = LoadRecents();
    size_t before = recents.size();
    recents.erase(std::remove_if(recents.begin(), recents.end(),
                                 [&](const RecentEntry& r){ return r.hash == hash; }), recents.end());
    if (recents.size() == before) return false;
    return writeRecents(recents);
}

} // namespace ds
