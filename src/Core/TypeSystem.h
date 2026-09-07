#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ds {

using TypeId = uint64_t;
using FieldId = uint64_t;
enum class TypeKind : uint8_t { Integer, Float, Pointer, Array, Structure, Union, Enum, Function };
struct TypeField { FieldId id = 0; std::string name; TypeId typeId = 0; uint64_t offsetBytes = 0; };
struct TypeEnumValue { std::string name; int64_t value = 0; };
struct TypeDefinition {
    TypeId id = 0;
    std::string name;
    TypeKind kind = TypeKind::Integer;
    uint64_t sizeBytes = 4;
    bool signedValue = false;
    TypeId targetType = 0; // pointer/array element; zero is void for pointers only
    uint64_t count = 0; // array count
    std::vector<TypeField> fields;
    std::vector<TypeEnumValue> enumValues;
    std::vector<TypeField> parameters; // offsetBytes must be zero
    TypeId returnType = 0; // zero is void
    std::string callingConvention;
};
struct TypeApplication { uint64_t address = 0; TypeId typeId = 0; std::string name; };
struct TypeRegistry {
    std::vector<TypeDefinition> types;
    std::vector<TypeApplication> applications;
    bool empty() const { return types.empty() && applications.empty(); }
};
inline constexpr size_t kMaxTypeDefinitions = 4096;
inline constexpr size_t kMaxTypeMembers = 1024;
inline constexpr size_t kMaxTotalTypeMembers = 16384;
inline constexpr size_t kMaxTypeApplications = 16384;
inline constexpr uint64_t kMaxTypeSizeBytes = uint64_t{1} << 30;

inline const char* TypeKindName(TypeKind kind) {
    switch (kind) {
        case TypeKind::Integer: return "Integer"; case TypeKind::Float: return "Float";
        case TypeKind::Pointer: return "Pointer"; case TypeKind::Array: return "Array";
        case TypeKind::Structure: return "Structure"; case TypeKind::Union: return "Union";
        case TypeKind::Enum: return "Enum"; case TypeKind::Function: return "Function";
    }
    return "Unknown";
}
inline const TypeDefinition* FindType(const TypeRegistry& registry, TypeId id) {
    for (const auto& type : registry.types) if (type.id == id && id) return &type;
    return nullptr;
}
inline TypeDefinition* FindType(TypeRegistry& registry, TypeId id) {
    for (auto& type : registry.types) if (type.id == id && id) return &type;
    return nullptr;
}
inline const TypeField* FindField(const TypeRegistry& registry, FieldId id) {
    for (const auto& type : registry.types) {
        for (const auto& field : type.fields) if (field.id == id && id) return &field;
        for (const auto& field : type.parameters) if (field.id == id && id) return &field;
    }
    return nullptr;
}
inline TypeId NextTypeId(const TypeRegistry& registry) {
    TypeId maximum = 0;
    for (const auto& type : registry.types) maximum = (std::max)(maximum, type.id);
    return maximum == UINT64_MAX ? 0 : maximum + 1;
}
inline FieldId NextFieldId(const TypeRegistry& registry) {
    FieldId maximum = 0;
    for (const auto& type : registry.types) {
        for (const auto& field : type.fields) maximum = (std::max)(maximum, field.id);
        for (const auto& field : type.parameters) maximum = (std::max)(maximum, field.id);
    }
    return maximum == UINT64_MAX ? 0 : maximum + 1;
}
inline bool TypeIdentifierValid(const std::string& name) {
    if (name.empty() || name.size() > 96) return false;
    auto alpha = [](unsigned char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'; };
    if (!alpha(static_cast<unsigned char>(name[0]))) return false;
    return std::all_of(name.begin() + 1, name.end(), [&](unsigned char c) { return alpha(c) || (c >= '0' && c <= '9'); });
}

// Validate a complete prospective registry before replacing project metadata.
// Pointer edges break value cycles; a structure may therefore point to itself
// but cannot contain itself. IDs remain identities when definitions are edited.
inline bool ValidateTypeRegistry(const TypeRegistry& registry, std::string* error = nullptr) {
    auto fail = [&](const std::string& message) { if (error) *error = message; return false; };
    if (error) error->clear();
    if (registry.types.size() > kMaxTypeDefinitions || registry.applications.size() > kMaxTypeApplications)
        return fail("Type or application limit exceeded");
    std::unordered_map<TypeId, const TypeDefinition*> types;
    std::unordered_set<std::string> names;
    std::unordered_set<FieldId> fieldIds;
    size_t members = 0;
    for (const auto& type : registry.types) {
        if (!type.id || !types.emplace(type.id, &type).second) return fail("Type IDs must be unique and nonzero");
        if (!TypeIdentifierValid(type.name) || !names.insert(type.name).second) return fail("Type names must be unique identifiers");
        if (type.kind > TypeKind::Function || type.sizeBytes > kMaxTypeSizeBytes) return fail("Invalid type kind or size");
        if (type.fields.size() > kMaxTypeMembers || type.parameters.size() > kMaxTypeMembers || type.enumValues.size() > kMaxTypeMembers)
            return fail("Type member limit exceeded");
        members += type.fields.size() + type.parameters.size() + type.enumValues.size();
        if (members > kMaxTotalTypeMembers) return fail("Total type member limit exceeded");
    }
    auto lookup = [&](TypeId id) -> const TypeDefinition* { const auto found = types.find(id); return found == types.end() ? nullptr : found->second; };
    auto scalarSize = [](uint64_t size) { return size == 1 || size == 2 || size == 4 || size == 8; };
    for (const auto& type : registry.types) {
        const bool aggregate = type.kind == TypeKind::Structure || type.kind == TypeKind::Union;
        if ((!aggregate && !type.fields.empty()) || (type.kind != TypeKind::Function && !type.parameters.empty()) ||
            (type.kind != TypeKind::Enum && !type.enumValues.empty())) return fail("Members do not match the type kind");
        if (type.kind != TypeKind::Pointer && type.kind != TypeKind::Array && type.targetType)
            return fail("Element type is only valid for pointers and arrays");
        if (type.kind != TypeKind::Array && type.count) return fail("Element count is only valid for arrays");
        if (type.kind != TypeKind::Function && (type.returnType || !type.callingConvention.empty()))
            return fail("Signature properties require a function type");
        if (type.kind != TypeKind::Integer && type.kind != TypeKind::Enum && type.signedValue)
            return fail("Signedness requires an integer or enum type");
        if (type.kind == TypeKind::Integer || type.kind == TypeKind::Enum) {
            if (!scalarSize(type.sizeBytes)) return fail("Integer and enum size must be 1, 2, 4, or 8 bytes");
        } else if (type.kind == TypeKind::Float) {
            if (type.sizeBytes != 4 && type.sizeBytes != 8) return fail("Float size must be 4 or 8 bytes");
        } else if (type.kind == TypeKind::Pointer) {
            if ((type.sizeBytes != 4 && type.sizeBytes != 8) || (type.targetType && !lookup(type.targetType)))
                return fail("Pointer requires a 4/8-byte width and a valid target or void");
        } else if (type.kind == TypeKind::Array) {
            const auto* element = lookup(type.targetType);
            if (!element || !element->sizeBytes || element->kind == TypeKind::Function || !type.count ||
                type.count > kMaxTypeSizeBytes / element->sizeBytes || type.sizeBytes != type.count * element->sizeBytes)
                return fail("Array count, element type, and byte size disagree");
        } else if (aggregate) {
            if (!type.sizeBytes) return fail("Structure and union size must be nonzero");
        } else if (type.kind == TypeKind::Function) {
            if (type.sizeBytes) return fail("Function signatures have no data size");
            if (!type.callingConvention.empty() && !TypeIdentifierValid(type.callingConvention))
                return fail("Calling convention must be an identifier");
            if (type.returnType && (!lookup(type.returnType) || lookup(type.returnType)->kind == TypeKind::Function))
                return fail("Invalid function return type");
        }
        std::unordered_set<std::string> localNames;
        std::vector<std::pair<uint64_t, uint64_t>> spans;
        auto validateField = [&](const TypeField& field, bool parameter) {
            if (!field.id || !fieldIds.insert(field.id).second || !TypeIdentifierValid(field.name) || !localNames.insert(field.name).second)
                return fail("Field and parameter IDs must be unique; names must be distinct identifiers");
            const auto* value = lookup(field.typeId);
            if (!value || value->kind == TypeKind::Function || !value->sizeBytes) return fail("Field or parameter has an invalid value type");
            if (parameter) { if (field.offsetBytes) return fail("Signature parameter offsets must be zero"); }
            else {
                if (field.offsetBytes > type.sizeBytes || value->sizeBytes > type.sizeBytes - field.offsetBytes)
                    return fail("Field " + type.name + "." + field.name + " extends past its containing type; enlarge the parent layout first");
                if (type.kind == TypeKind::Union && field.offsetBytes) return fail("Union fields must start at zero");
                spans.emplace_back(field.offsetBytes, field.offsetBytes + value->sizeBytes);
            }
            return true;
        };
        for (const auto& field : type.fields) if (!validateField(field, false)) return false;
        for (const auto& field : type.parameters) if (!validateField(field, true)) return false;
        if (type.kind == TypeKind::Structure) {
            std::sort(spans.begin(), spans.end());
            for (size_t i = 1; i < spans.size(); ++i)
                if (spans[i].first < spans[i-1].second) return fail("Structure fields overlap; use a union for overlapping members");
        }
        for (const auto& item : type.enumValues) {
            if (!TypeIdentifierValid(item.name) || !localNames.insert(item.name).second) return fail("Enum names must be distinct identifiers");
            const unsigned bits = static_cast<unsigned>(type.sizeBytes * 8);
            if (type.signedValue) {
                if (bits < 64 && (item.value < -(int64_t{1} << (bits-1)) || item.value > (int64_t{1} << (bits-1))-1))
                    return fail("Enum value does not fit its signed width");
            } else if (item.value < 0 || (bits < 64 && static_cast<uint64_t>(item.value) >= (uint64_t{1} << bits)))
                return fail("Enum value does not fit its unsigned width");
        }
    }
    std::unordered_map<TypeId, uint8_t> state;
    std::function<bool(TypeId, unsigned)> visit = [&](TypeId id, unsigned depth) {
        if (!id) return true;
        if (depth > 256) return fail("Type dependency depth exceeds 256");
        if (state[id] == 1) return fail("Type contains a value cycle; use a pointer for recursive data");
        if (state[id] == 2) return true;
        state[id] = 1;
        const auto* type = lookup(id);
        if (!type) return fail("Type reference does not exist");
        if (type->kind == TypeKind::Array && !visit(type->targetType, depth+1)) return false;
        for (const auto& field : type->fields) if (!visit(field.typeId, depth+1)) return false;
        for (const auto& parameter : type->parameters) if (!visit(parameter.typeId, depth+1)) return false;
        if (type->kind == TypeKind::Function && !visit(type->returnType, depth+1)) return false;
        state[id] = 2;
        return true;
    };
    for (const auto& type : registry.types) if (!visit(type.id, 0)) return false;
    names.clear();
    std::vector<std::pair<uint64_t, uint64_t>> appliedSpans;
    for (const auto& application : registry.applications) {
        const auto* type = lookup(application.typeId);
        if (!type || !type->sizeBytes || type->kind == TypeKind::Function ||
            application.address > UINT64_MAX - (type->sizeBytes - 1)) return fail("Global type application has invalid type or address extent");
        if (!TypeIdentifierValid(application.name) || !names.insert(application.name).second)
            return fail("Global names must be unique identifiers");
        appliedSpans.emplace_back(application.address, application.address + type->sizeBytes - 1);
    }
    std::sort(appliedSpans.begin(), appliedSpans.end());
    for (size_t i = 1; i < appliedSpans.size(); ++i)
        if (appliedSpans[i].first <= appliedSpans[i-1].second) return fail("Global type applications overlap");
    return true;
}

// Array byte sizes are derived from their element definitions. Recompute the
// complete dependency chain when an analyst edits an element size. A failed
// computation leaves every definition untouched; callers still validate the
// resulting registry's field layouts and application extents before publishing.
inline bool RecomputeTypeArraySizes(TypeRegistry& registry, std::string* error = nullptr) {
    auto fail = [&](const std::string& message) { if (error) *error = message; return false; };
    if (error) error->clear();
    if (registry.types.size() > kMaxTypeDefinitions) return fail("Type definition limit exceeded");
    std::unordered_map<TypeId, size_t> indices;
    std::vector<uint64_t> sizes;
    sizes.reserve(registry.types.size());
    for (size_t i = 0; i < registry.types.size(); ++i) {
        const auto& type = registry.types[i];
        if (!type.id || !indices.emplace(type.id, i).second) return fail("Type IDs must be unique and nonzero");
        sizes.push_back(type.sizeBytes);
    }
    std::vector<uint8_t> state(registry.types.size(), 0);
    std::function<bool(size_t, unsigned)> visit = [&](size_t index, unsigned depth) {
        const auto& type = registry.types[index];
        if (type.kind != TypeKind::Array) return true;
        if (depth > 256) return fail("Array dependency depth exceeds 256");
        if (state[index] == 1) return fail("Array element dependency is cyclic");
        if (state[index] == 2) return true;
        state[index] = 1;
        const auto found = indices.find(type.targetType);
        if (found == indices.end()) return fail("Array " + type.name + " has no valid element type");
        const size_t elementIndex = found->second;
        if (!visit(elementIndex, depth+1)) return false;
        const uint64_t elementSize = sizes[elementIndex];
        if (registry.types[elementIndex].kind == TypeKind::Function || !elementSize || !type.count ||
            elementSize > kMaxTypeSizeBytes || type.count > kMaxTypeSizeBytes / elementSize)
            return fail("Array " + type.name + " count or element size exceeds the byte-size limit");
        sizes[index] = elementSize * type.count;
        state[index] = 2;
        return true;
    };
    for (size_t i = 0; i < registry.types.size(); ++i) if (!visit(i, 0)) return false;
    for (size_t i = 0; i < registry.types.size(); ++i)
        if (registry.types[i].kind == TypeKind::Array) registry.types[i].sizeBytes = sizes[i];
    return true;
}

// Exact field slices only. A union with several matching fields is ambiguous;
// the analyst must select a member rather than getting an invented field name.
inline const TypeField* ResolveTypeFieldAt(const TypeRegistry& registry, TypeId id,
                                         uint64_t offsetBytes, uint64_t widthBytes) {
    const auto* type = FindType(registry, id);
    if (!type || !widthBytes) return nullptr;
    const TypeField* found = nullptr;
    for (const auto& field : type->fields) {
        const auto* fieldType = FindType(registry, field.typeId);
        if (field.offsetBytes == offsetBytes && fieldType && fieldType->sizeBytes == widthBytes) {
            if (found) return nullptr;
            found = &field;
        }
    }
    return found;
}

} // namespace ds
