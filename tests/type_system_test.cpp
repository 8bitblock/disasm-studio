#include "Core/TypeSystem.h"
#include <cstdio>
#include <limits>

using namespace ds;
static int failures = 0;
#define CHECK(value) do { if (!(value)) { std::printf("FAIL line %d: %s\n", __LINE__, #value); ++failures; } } while (0)

static TypeRegistry fixture() {
    TypeRegistry result;
    TypeDefinition integer; integer.id = 1; integer.name = "i32"; integer.signedValue = true;
    TypeDefinition record; record.id = 2; record.name = "Player"; record.kind = TypeKind::Structure; record.sizeBytes = 16;
    record.fields = { {1, "health", 1, 0}, {2, "next", 3, 8} };
    TypeDefinition pointer; pointer.id = 3; pointer.name = "PlayerPtr"; pointer.kind = TypeKind::Pointer; pointer.sizeBytes = 8; pointer.targetType = 2;
    TypeDefinition array; array.id = 4; array.name = "Players"; array.kind = TypeKind::Array; array.targetType = 2; array.count = 10; array.sizeBytes = 160;
    TypeDefinition enumeration; enumeration.id = 5; enumeration.name = "State"; enumeration.kind = TypeKind::Enum; enumeration.sizeBytes = 1;
    enumeration.signedValue = true; enumeration.enumValues = { {"Denied", -1}, {"Allowed", 1} };
    TypeDefinition signature; signature.id = 6; signature.name = "CheckPlayer"; signature.kind = TypeKind::Function; signature.sizeBytes = 0;
    signature.returnType = 5; signature.parameters = { {3, "player", 3, 0} }; signature.callingConvention = "Win64";
    TypeDefinition floating; floating.id = 7; floating.name = "f32"; floating.kind = TypeKind::Float;
    TypeDefinition overlay; overlay.id = 8; overlay.name = "Bits"; overlay.kind = TypeKind::Union;
    overlay.fields = { {4, "integer", 1, 0}, {5, "real", 7, 0} };
    result.types = { integer, record, pointer, array, enumeration, signature, floating, overlay };
    result.applications = { {0, 2, "player"}, {0x100, 4, "players"} };
    return result;
}

int main() {
    auto registry = fixture();
    std::string error;
    CHECK(ValidateTypeRegistry(registry, &error) && error.empty());
    CHECK(NextTypeId(registry) == 9 && NextFieldId(registry) == 6);
    const auto* field = ResolveTypeFieldAt(registry, 2, 0, 4);
    CHECK(field && field->id == 1 && field->name == "health");
    CHECK(!ResolveTypeFieldAt(registry, 2, 0, 8));
    CHECK(!ResolveTypeFieldAt(registry, 2, 1, 4));
    CHECK(!ResolveTypeFieldAt(registry, 8, 0, 4)); // ambiguous union
    FindType(registry, 2)->fields[0].name = "hitPoints";
    CHECK(FindField(registry, 1)->name == "hitPoints");

    auto rejects = [&](auto mutation) {
        auto changed = fixture(); mutation(changed); error.clear();
        CHECK(!ValidateTypeRegistry(changed, &error) && !error.empty());
    };
    rejects([](auto& r) { r.types[0].id = 0; });
    rejects([](auto& r) { r.types[1].id = 1; });
    rejects([](auto& r) { r.types[1].name = "i32"; });
    rejects([](auto& r) { r.types[1].name = "bad;name"; });
    rejects([](auto& r) { r.types[1].fields[0].id = 2; });
    rejects([](auto& r) { r.types[1].fields[0].typeId = 99; });
    rejects([](auto& r) { r.types[1].fields = {{1, "self", 2, 0}}; }); // layout fits; direct value cycle
    rejects([](auto& r) { r.types[1].fields[1].offsetBytes = 1; });
    rejects([](auto& r) { r.types[1].fields[1].offsetBytes = UINT64_MAX; });
    rejects([](auto& r) { r.types[2].targetType = 99; });
    rejects([](auto& r) { r.types[2].sizeBytes = 3; });
    rejects([](auto& r) { r.types[3].count = UINT64_MAX; });
    rejects([](auto& r) { r.types[3].sizeBytes = 159; });
    rejects([](auto& r) { r.types[3].targetType = 4; r.types[3].count = 1; }); // size fits; array value cycle
    rejects([](auto& r) { r.types[4].enumValues[0].value = -129; });
    rejects([](auto& r) { r.types[4].signedValue = false; });
    rejects([](auto& r) { r.types[4].enumValues[1].name = "Denied"; });
    rejects([](auto& r) { r.types[5].parameters[0].offsetBytes = 1; });
    rejects([](auto& r) { r.types[5].returnType = 6; });
    rejects([](auto& r) { r.types[6].sizeBytes = 1; });
    rejects([](auto& r) { r.types[7].fields[0].offsetBytes = 1; });
    rejects([](auto& r) { r.applications[1].address = 4; });
    rejects([](auto& r) { r.applications[1].address = UINT64_MAX; });
    rejects([](auto& r) { r.applications[1].typeId = 6; });
    rejects([](auto& r) { r.applications[1].name = "player"; });
    rejects([](auto& r) { r.types[0].kind = static_cast<TypeKind>(255); });
    rejects([](auto& r) { r.types[0].fields.push_back({6, "unexpected", 1, 0}); });

    registry = fixture();
    registry.types[2].targetType = 0; // void pointer
    registry.types[4].sizeBytes = 8;
    registry.types[4].enumValues[0].value = INT64_MIN;
    CHECK(ValidateTypeRegistry(registry));
    registry.types[0].id = UINT64_MAX;
    CHECK(NextTypeId(registry) == 0); // explicit exhaustion
    registry.types[1].fields[0].id = UINT64_MAX;
    CHECK(NextFieldId(registry) == 0);
    CHECK(!TypeIdentifierValid("0bad") && !TypeIdentifierValid(std::string(97, 'a')));
    registry = fixture();
    TypeDefinition nested; nested.id = 9; nested.name = "PlayerGrid";
    nested.kind = TypeKind::Array; nested.targetType = 4; nested.count = 3; nested.sizeBytes = 480;
    registry.types.push_back(nested);
    registry.types[1].sizeBytes = 32;
    CHECK(RecomputeTypeArraySizes(registry, &error));
    CHECK(FindType(registry, 4)->sizeBytes == 320 && FindType(registry, 9)->sizeBytes == 960);
    CHECK(ValidateTypeRegistry(registry));
    registry.types[1].sizeBytes = 64;
    FindType(registry, 9)->count = UINT64_MAX;
    CHECK(!RecomputeTypeArraySizes(registry, &error) && !error.empty());
    CHECK(FindType(registry, 4)->sizeBytes == 320 && FindType(registry, 9)->sizeBytes == 960);
    FindType(registry, 9)->count = 3;
    FindType(registry, 4)->targetType = 9;
    CHECK(!RecomputeTypeArraySizes(registry, &error));
    CHECK(FindType(registry, 4)->sizeBytes == 320 && FindType(registry, 9)->sizeBytes == 960);
    FindType(registry, 4)->targetType = 999;
    CHECK(!RecomputeTypeArraySizes(registry, &error));
    CHECK(FindType(registry, 4)->sizeBytes == 320);
    if (failures) return 1;
    std::puts("type_system_test: all checks passed");
    return 0;
}
