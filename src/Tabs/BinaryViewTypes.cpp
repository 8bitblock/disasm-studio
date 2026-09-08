#include "BinaryViewTab.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace ds {
namespace {
bool editTypeText(const char* label, std::string& value) {
    char buffer[128]{};
    std::snprintf(buffer, sizeof(buffer), "%s", value.c_str());
    if (!ImGui::InputText(label, buffer, sizeof(buffer))) return false;
    value = buffer;
    return true;
}
bool chooseType(const char* label, TypeId& id, const TypeRegistry& registry, bool allowVoid) {
    const auto* selected = FindType(registry, id);
    const char* preview = selected ? selected->name.c_str() : id ? "Missing type" : allowVoid ? "void" : "Choose type";
    bool changed = false;
    if (ImGui::BeginCombo(label, preview)) {
        if (allowVoid && ImGui::Selectable("void", id == 0)) { id = 0; changed = true; }
        for (const auto& type : registry.types) {
            ImGui::PushID(static_cast<int>(type.id));
            if (ImGui::Selectable(type.name.c_str(), id == type.id)) { id = type.id; changed = true; }
            ImGui::PopID();
        }
        ImGui::EndCombo();
    }
    return changed;
}
}

void BinaryViewTab::renderTypedLocation(AppContext& ctx, uint64_t va) {
    const auto& registry = ctx.staticProject().typeRegistry;
    const TypeApplication* candidate = nullptr;
    for (const auto& application : registry.applications)
        if (application.address <= va && (!candidate || application.address > candidate->address))
            candidate = &application;
    if (candidate) {
        const auto& application = *candidate;
        const auto* type = FindType(registry, application.typeId);
        if (!type || va - application.address >= type->sizeBytes) return;
        const uint64_t offset = va - application.address;
        ImGui::TextColored(theme::col::accent(), "%s : %s  +0x%llX", application.name.c_str(),
            type->name.c_str(), static_cast<unsigned long long>(offset));
        ui::SameLineIfFits(115.0f * theme::UiScale());
        ImGui::BeginDisabled(typeDraftDirty_);
        if (ImGui::SmallButton("Open definition")) {
            typeDraft_ = *type;
            typeDraftDirty_ = false;
            typeDraftImage_ = investigationImageSerial_;
            focusTypesTab_ = lowerAdvancedMode_ = true;
            lowerDockCollapsed_ = false;
        }
        ImGui::EndDisabled();
        ui::ItemTooltip("Open the shared definition. Save or discard an existing draft first.");
        const TypeField* match = nullptr;
        bool ambiguous = false;
        for (const auto& field : type->fields) {
            const auto* fieldType = FindType(registry, field.typeId);
            if (fieldType && offset >= field.offsetBytes && offset - field.offsetBytes < fieldType->sizeBytes) {
                if (match) ambiguous = true;
                match = &field;
            }
        }
        if (match && !ambiguous) {
            const auto* fieldType = FindType(registry, match->typeId);
            ImGui::TextDisabled("%s.%s  %s  field +0x%llX, byte +0x%llX",
                application.name.c_str(), match->name.c_str(), fieldType->name.c_str(),
                static_cast<unsigned long long>(match->offsetBytes),
                static_cast<unsigned long long>(offset - match->offsetBytes));
        } else if (ambiguous) ImGui::TextDisabled("Overlapping union members; no active member is inferred.");
        return;
    }
}

bool BinaryViewTab::saveTypeDraft(AppContext& ctx, bool persist, std::string& error) {
    if (!typeDraftDirty_) return true;
    if (!ctx.commitTypeDefinition(documentId_, typeDraftGeneration_, typeDraft_, persist, error)) return false;
    typeDraftDirty_ = false;
    return true;
}

void BinaryViewTab::discardTypeDraft(AppContext& ctx) {
    typeDraft_ = {};
    typeDraftDirty_ = false;
    typeStatus_.clear();
    ctx.setTypeDraftPending(documentId_, false);
}

void BinaryViewTab::renderTypeWorkbench(AppContext& ctx) {
    const bool focus = focusTypesTab_;
    if (!ImGui::BeginTabItem("Types", nullptr, focus ? ImGuiTabItemFlags_SetSelected : 0)) return;
    focusTypesTab_ = false;
    if (typeDraftImage_ != investigationImageSerial_) {
        // Decoder/analysis changes may retire presentation state in the same
        // document. Never discard an unsaved definition on that refresh edge.
        if (!typeDraftDirty_) {
            typeDraft_ = {}; typeStatus_.clear();
            typeApplicationName_[0] = 0;
            typeDraftGeneration_ = ctx.staticImageGeneration();
        }
        typeDraftImage_ = investigationImageSerial_;
    }
    if (!typeDraftDirty_) typeDraftGeneration_ = ctx.staticImageGeneration();
    auto& registry = ctx.staticProject().typeRegistry;
    const float scale = theme::UiScale();
    ImGui::BeginChild("##type_workbench", ImVec2(0, 0));
    ImGui::TextDisabled("Shared definitions / FILE memory  |  %zu types, %zu applications", registry.types.size(), registry.applications.size());
    const bool dirty = typeDraftDirty_;
    ImGui::BeginDisabled(dirty || registry.types.size() >= kMaxTypeDefinitions);
    if (ImGui::Button("New type")) {
        const auto nextId = NextTypeId(registry);
        if (!nextId) {
            typeStatus_ = "No more type identities are available in this document.";
        } else {
            typeDraft_ = {};
            typeDraft_.id = nextId;
            typeDraft_.name = "type_" + std::to_string(nextId);
            typeDraftDirty_ = true;
            typeStatus_.clear();
        }
    }
    ImGui::EndDisabled();
    ui::ItemTooltip(dirty ? "Save or discard the current draft before opening another definition." : "Create a reusable definition with a stable identity.");
    ui::SameLineIfFits(130.0f * scale);
    ImGui::BeginDisabled(dirty);
    if (ImGui::Button("Add scalar types")) {
        TypeRegistry proposed = registry;
        const char* names[] = {"uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "float32", "float64"};
        for (int i = 0; i < 10; ++i) {
            if (std::any_of(proposed.types.begin(), proposed.types.end(), [&](const auto& t) { return t.name == names[i]; })) continue;
            TypeDefinition type;
            type.id = NextTypeId(proposed); type.name = names[i];
            type.kind = i < 8 ? TypeKind::Integer : TypeKind::Float;
            type.sizeBytes = i < 8 ? uint64_t{1} << (i % 4) : i == 8 ? 4 : 8;
            type.signedValue = i >= 4 && i < 8;
            proposed.types.push_back(std::move(type));
        }
        if (ValidateTypeRegistry(proposed, &typeStatus_)) { registry = std::move(proposed); ctx.markProjectDirty(); }
    }
    ImGui::EndDisabled();
    ui::SameLineIfFits(220.0f * scale);
    ui::SearchBox("##type_filter", "Find a definition...", typeFilter_, sizeof(typeFilter_), std::min(240.0f * scale, ImGui::GetContentRegionAvail().x));

    // Native combo keeps the complete library reachable at short drawer heights.
    ImGui::SetNextItemWidth(-1);
    ImGui::BeginDisabled(typeDraftDirty_);
    if (ImGui::BeginCombo("##type_definition", typeDraft_.id ? typeDraft_.name.c_str() : "Select a definition")) {
        for (const auto& type : registry.types) {
            if (typeFilter_[0] && type.name.find(typeFilter_) == std::string::npos) continue;
            if (ImGui::Selectable(type.name.c_str(), type.id == typeDraft_.id)) {
                typeDraft_ = type; typeDraftDirty_ = false; typeStatus_.clear();
            }
        }
        ImGui::EndCombo();
    }
    ImGui::EndDisabled();
    if (typeDraft_.id) {
        ImGui::Separator();
        ImGui::SetNextItemWidth(240.0f * scale);
        typeDraftDirty_ |= editTypeText("Name", typeDraft_.name);
        ui::SameLineIfFits(210.0f * scale);
        ImGui::SetNextItemWidth(140.0f * scale);
        const char* kinds[] = {"Integer", "Float", "Pointer", "Array", "Structure", "Union", "Enum", "Function"};
        int kind = static_cast<int>(typeDraft_.kind);
        if (ImGui::Combo("Kind", &kind, kinds, 8)) {
            const auto id = typeDraft_.id; const auto name = typeDraft_.name;
            typeDraft_ = {}; typeDraft_.id = id; typeDraft_.name = name;
            typeDraft_.kind = static_cast<TypeKind>(kind);
            if (typeDraft_.kind == TypeKind::Function) typeDraft_.sizeBytes = 0;
            if (typeDraft_.kind == TypeKind::Array) typeDraft_.count = 1;
            if (typeDraft_.kind == TypeKind::Pointer) {
                const Arch arch = ctx.staticArch();
                typeDraft_.sizeBytes = arch == Arch::X64 || arch == Arch::ARM64 || arch == Arch::MIPS64 ||
                    arch == Arch::PPC64 || arch == Arch::RISCV64 ? 8 : 4;
            }
            typeDraftDirty_ = true;
        }
        if (typeDraft_.kind != TypeKind::Function) {
            ImGui::SetNextItemWidth(170.0f * scale);
            typeDraftDirty_ |= ImGui::InputScalar("Size (bytes)", ImGuiDataType_U64, &typeDraft_.sizeBytes);
        }
        if (typeDraft_.kind == TypeKind::Integer || typeDraft_.kind == TypeKind::Enum) {
            ui::SameLineIfFits(95.0f * scale);
            typeDraftDirty_ |= ImGui::Checkbox("Signed", &typeDraft_.signedValue);
        }
        if (typeDraft_.kind == TypeKind::Pointer || typeDraft_.kind == TypeKind::Array) {
            ImGui::SetNextItemWidth(230.0f * scale);
            typeDraftDirty_ |= chooseType("Element type", typeDraft_.targetType, registry, typeDraft_.kind == TypeKind::Pointer);
            if (typeDraft_.kind == TypeKind::Array) {
                ImGui::SetNextItemWidth(170.0f * scale);
                typeDraftDirty_ |= ImGui::InputScalar("Element count", ImGuiDataType_U64, &typeDraft_.count);
                if (const auto* element = FindType(registry, typeDraft_.targetType); element &&
                    typeDraft_.count && element->sizeBytes <= kMaxTypeSizeBytes / typeDraft_.count) {
                    const uint64_t size = element->sizeBytes * typeDraft_.count;
                    if (size != typeDraft_.sizeBytes) { typeDraft_.sizeBytes = size; typeDraftDirty_ = true; }
                }
            }
        }
        const bool function = typeDraft_.kind == TypeKind::Function;
        const bool aggregate = typeDraft_.kind == TypeKind::Structure || typeDraft_.kind == TypeKind::Union;
        if (function) {
            ImGui::SetNextItemWidth(230.0f * scale);
            typeDraftDirty_ |= chooseType("Return type", typeDraft_.returnType, registry, true);
            ImGui::SetNextItemWidth(230.0f * scale);
            typeDraftDirty_ |= editTypeText("Calling convention", typeDraft_.callingConvention);
        }
        if (aggregate || function) {
            auto& fields = function ? typeDraft_.parameters : typeDraft_.fields;
            ImGui::BeginDisabled(fields.size() >= kMaxTypeMembers);
            if (ImGui::SmallButton(function ? "Add parameter" : "Add field")) {
                FieldId next = NextFieldId(registry);
                for (const auto& field : fields) next = std::max(next, field.id == UINT64_MAX ? 0 : field.id + 1);
                if (next) fields.push_back({next, (function ? "arg_" : "field_") + std::to_string(fields.size()), 0, 0});
                typeDraftDirty_ = true;
            }
            ImGui::EndDisabled();
            if (ui::BeginDataTable("##type_fields", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerH)) {
                ImGui::TableSetupColumn("Name"); ImGui::TableSetupColumn("Type");
                ImGui::TableSetupColumn(function ? "" : "Offset (bytes)");
                ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 40.0f * scale);
                ImGui::TableHeadersRow();
                int remove = -1;
                for (size_t i = 0; i < fields.size(); ++i) {
                    auto& field = fields[i];
                    ImGui::PushID(static_cast<int>(i)); ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::SetNextItemWidth(-1);
                    typeDraftDirty_ |= editTypeText("##field_name", field.name);
                    ImGui::TableSetColumnIndex(1); ImGui::SetNextItemWidth(-1);
                    typeDraftDirty_ |= chooseType("##field_type", field.typeId, registry, false);
                    ImGui::TableSetColumnIndex(2); ImGui::SetNextItemWidth(-1);
                    if (aggregate) typeDraftDirty_ |= ImGui::InputScalar("##field_offset", ImGuiDataType_U64, &field.offsetBytes);
                    ImGui::TableSetColumnIndex(3);
                    if (ImGui::SmallButton("x")) remove = static_cast<int>(i);
                    ImGui::PopID();
                }
                if (remove >= 0) { fields.erase(fields.begin() + remove); typeDraftDirty_ = true; }
                ui::EndDataTable();
            }
        }
        if (typeDraft_.kind == TypeKind::Enum) {
            ImGui::BeginDisabled(typeDraft_.enumValues.size() >= kMaxTypeMembers);
            if (ImGui::SmallButton("Add enum value")) {
                typeDraft_.enumValues.push_back({"value_" + std::to_string(typeDraft_.enumValues.size()), 0});
                typeDraftDirty_ = true;
            }
            ImGui::EndDisabled();
            int remove = -1;
            for (size_t i = 0; i < typeDraft_.enumValues.size(); ++i) {
                auto& value = typeDraft_.enumValues[i]; ImGui::PushID(static_cast<int>(i));
                ImGui::SetNextItemWidth(200.0f * scale); typeDraftDirty_ |= editTypeText("##enum_name", value.name);
                ui::SameLineIfFits(160.0f * scale); ImGui::SetNextItemWidth(150.0f * scale);
                typeDraftDirty_ |= ImGui::InputScalar("##enum_value", ImGuiDataType_S64, &value.value);
                ImGui::SameLine(); if (ImGui::SmallButton("x")) remove = static_cast<int>(i);
                ImGui::PopID();
            }
            if (remove >= 0) { typeDraft_.enumValues.erase(typeDraft_.enumValues.begin()+remove); typeDraftDirty_ = true; }
        }
        ImGui::BeginDisabled(!typeDraftDirty_);
        if (ui::AccentButton("Save definition", theme::col::accent())) {
            if (saveTypeDraft(ctx, false, typeStatus_))
                typeStatus_ = "Definition saved. Applied locations use this definition immediately.";
        }
        ImGui::EndDisabled(); ImGui::SameLine();
        if (ImGui::Button("Discard draft")) {
            discardTypeDraft(ctx);
        }
        if (typeDraftDirty_) { ui::SameLineIfFits(130.0f * scale); ImGui::TextColored(theme::col::warn(), "Unsaved definition"); }
        ImGui::SeparatorText("Apply to FILE memory");
        ImGui::SetNextItemWidth(230.0f * scale);
        ImGui::InputTextWithHint("Global name", "e.g. player", typeApplicationName_, sizeof(typeApplicationName_));
        const bool canApply = !typeDraftDirty_ && FindType(registry, typeDraft_.id) &&
            typeDraft_.kind != TypeKind::Function && cursorValid_ && !cursorLive_;
        ImGui::BeginDisabled(!canApply);
        if (ImGui::Button("Apply at selected address")) {
            size_t available = 0;
            if (!ctx.staticBinary().ptrFromVA(cursorVA_, available) || typeDraft_.sizeBytes > available)
                typeStatus_ = "The complete type must fit in backed FILE memory at the selected address.";
            else {
                TypeRegistry proposed = registry;
                auto found = std::find_if(proposed.applications.begin(), proposed.applications.end(), [&](const auto& a) { return a.address == cursorVA_; });
                TypeApplication application{cursorVA_, typeDraft_.id, typeApplicationName_};
                if (found == proposed.applications.end()) proposed.applications.push_back(application);
                else *found = application;
                if (ValidateTypeRegistry(proposed, &typeStatus_)) {
                    registry = std::move(proposed); ctx.markProjectDirty();
                    typeStatus_ = "Applied to FILE memory. Hex and Address Inspector share this definition.";
                }
            }
        }
        ImGui::EndDisabled();
        ui::ItemTooltip("Select a backed FILE address, save the definition, and enter a unique global name. This adds analyst metadata without changing bytes or code classification.");
        if (function) ImGui::TextDisabled("Signature definitions are reusable metadata; assigning arguments and locals is not yet supported.");
    }
    if (!typeStatus_.empty()) ImGui::TextWrapped("%s", typeStatus_.c_str());
    if (!registry.applications.empty() && ImGui::CollapsingHeader("Applied locations", ImGuiTreeNodeFlags_DefaultOpen)) {
        int removeApplication = -1;
        ImGuiListClipper clip; clip.Begin(static_cast<int>(registry.applications.size()));
        while (clip.Step()) for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            const auto& a = registry.applications[i]; const auto* type = FindType(registry, a.typeId);
            char label[300]; std::snprintf(label, sizeof(label), "%s : %s  @ 0x%llX", a.name.c_str(),
                type ? type->name.c_str() : "Missing type", static_cast<unsigned long long>(a.address));
            if (ImGui::Selectable(label)) navigateToStaticView(a.address, DocumentView::Hex);
            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem("Remove type application")) removeApplication = i;
                ImGui::EndPopup();
            }
        }
        if (removeApplication >= 0) {
            registry.applications.erase(registry.applications.begin() + removeApplication);
            ctx.markProjectDirty();
        }
    }
    ctx.setTypeDraftPending(documentId_, typeDraftDirty_);
    ImGui::EndChild();
    ImGui::EndTabItem();
}
} // namespace ds
