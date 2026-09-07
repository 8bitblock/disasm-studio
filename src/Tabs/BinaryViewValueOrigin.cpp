#include "BinaryViewTab.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"
#include <algorithm>
#include <cstdio>

namespace ds {
bool BinaryViewTab::valueOriginCurrent(AppContext& ctx) const {
    return ctx.staticBinary().loaded() && !functionsDirty_ && !patchRefresh_.pending() &&
        valueOrigin_.imageSerial == investigationImageSerial_ &&
        valueOrigin_.imageRevision == ctx.staticBinary().imageRevision() &&
        valueOrigin_.epoch == ctx.staticAnalysis().epoch() &&
        valueOrigin_.functionsGeneration == functionsGen_ &&
        valueOrigin_.decoder == ctx.staticDecoderConfig();
}

bool BinaryViewTab::valueOriginHighlights(AppContext& ctx, uint64_t va) const {
    return valueOrigin_.result && valueOriginCurrent(ctx) && valueOrigin_.highlighted.count(va) != 0;
}

void BinaryViewTab::adoptValueOriginResult(AppContext& ctx, const AnalysisResult& result) {
    if (!(result.kinds & K_ValueOrigin) || result.valueOriginRequestId != valueOrigin_.requestId ||
        result.epoch != valueOrigin_.epoch || !valueOrigin_.pending || !valueOriginCurrent(ctx)) return;
    valueOrigin_.pending = false;
    valueOrigin_.result = result.valueOrigin;
    valueOrigin_.highlighted.clear();
    valueOrigin_.status = result.failureValid ? result.failure :
        result.valueOrigin ? result.valueOrigin->status : "Value-origin analysis did not produce a result.";
    if (valueOrigin_.result)
        for (const auto& source : valueOrigin_.result->sources) valueOrigin_.highlighted.insert(source.va);
}

void BinaryViewTab::requestValueOrigin(AppContext& ctx, const std::string& registerName) {
    if (valueOrigin_.cancellation) valueOrigin_.cancellation->store(true, std::memory_order_release);
    valueOrigin_.pending = false;
    valueOrigin_.result.reset(); valueOrigin_.highlighted.clear();
    if (cursorLive_ || !cursorValid_ || !ArchIsX86_32Or64(ctx.staticArch()) ||
        functionsDirty_ || patchRefresh_.pending()) {
        valueOrigin_.status = "Select an analyzed FILE x86/x64 instruction."; return;
    }
    Instruction selected;
    std::string error;
    if (!decodeListingActionInstruction(ctx, cursorVA_, selected, error)) {
        valueOrigin_.status = error.empty() ? "Select an exact decoded instruction boundary." : error; return;
    }
    const Func* function = funcContaining(cursorVA_);
    if (!function) { valueOrigin_.status = "Select an instruction inside an analyzed function."; return; }
    auto request = std::make_shared<ValueOriginRequest>();
    request->requestId = ++valueOrigin_.requestId;
    if (!request->requestId) request->requestId = ++valueOrigin_.requestId;
    request->functionVA = function->address;
    request->instructionVA = cursorVA_;
    request->registerName = registerName;
    request->chunks = function->chunks;
    if (request->chunks.empty() && function->size) request->chunks.push_back({function->address, function->size});
    request->ownershipTruncated = function->ownershipTruncated;
    valueOrigin_.cancellation = std::make_shared<std::atomic<bool>>(false);
    request->cancellation = valueOrigin_.cancellation;
    valueOrigin_.imageSerial = investigationImageSerial_;
    valueOrigin_.imageRevision = ctx.staticBinary().imageRevision();
    valueOrigin_.epoch = ctx.staticAnalysis().epoch();
    valueOrigin_.functionsGeneration = functionsGen_;
    valueOrigin_.decoder = ctx.staticDecoderConfig();
    valueOrigin_.pending = true;
    valueOrigin_.idleFrames = 0;
    valueOrigin_.status = "Tracing register dependencies...";
    ctx.staticAnalysis().requestValueOrigin(&ctx.staticBinary(), ctx.staticDecoderConfig(),
                                          valueOrigin_.epoch, std::move(request));
}

void BinaryViewTab::renderValueOriginInspector(AppContext& ctx) {
    if ((valueOrigin_.pending || valueOrigin_.result) && !valueOriginCurrent(ctx)) {
        if (valueOrigin_.cancellation) valueOrigin_.cancellation->store(true, std::memory_order_release);
        valueOrigin_.pending = false; valueOrigin_.result.reset(); valueOrigin_.highlighted.clear();
        valueOrigin_.status = "Value origins retired because the image or analysis changed. Trace again to refresh.";
    }
    // A worker can finish between this frame's result drain and inspector render.
    // Allow the next drain to adopt its queued result before offering retry.
    if (valueOrigin_.pending && (ctx.staticAnalysis().pendingKinds() & K_ValueOrigin)) valueOrigin_.idleFrames = 0;
    if (valueOrigin_.pending && !(ctx.staticAnalysis().pendingKinds() & K_ValueOrigin) && ++valueOrigin_.idleFrames > 1) {
        valueOrigin_.pending = false;
        valueOrigin_.status = "Value-origin request ended without a result. Trace again to retry.";
    }
    if (valueOrigin_.reveal) { ImGui::SetNextItemOpen(true); valueOrigin_.reveal = false; }
    if (!ImGui::CollapsingHeader("Where did this value come from?")) return;
    ImGui::PushID("value_origin");
    const bool supported = !cursorLive_ && cursorValid_ && ArchIsX86_32Or64(ctx.staticArch()) &&
        !functionsDirty_ && !patchRefresh_.pending();
    if (!supported) ImGui::TextWrapped("Select an analyzed FILE x86/x64 instruction. Values are traced before that instruction executes.");
    std::vector<std::string> choices;
    auto add = [&](const std::string& name) {
        RegisterSlice reg;
        if (ValueOriginRegister(name, ctx.staticArch(), reg) &&
            std::find(choices.begin(), choices.end(), reg.name) == choices.end()) choices.push_back(reg.name);
    };
    if (supported) {
        Instruction selected;
        std::string ignored;
        if (decodeListingActionInstruction(ctx, cursorVA_, selected, ignored)) {
            for (const auto& operand : selected.typedOperands) {
                if (operand.kind == OperandKind::Register) add(operand.registerName);
                if (operand.kind == OperandKind::Memory) { add(operand.baseRegister); add(operand.indexRegister); }
            }
        }
        const char* defaults64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
        const char* defaults32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
        if (ctx.staticArch() == Arch::X64) for (const auto* reg : defaults64) add(reg);
        else for (const auto* reg : defaults32) add(reg);
    }
    if (!choices.empty() && std::find(choices.begin(), choices.end(), valueOrigin_.selectedRegister) == choices.end())
        valueOrigin_.selectedRegister = choices.front();
    ImGui::BeginDisabled(!supported || choices.empty());
    ImGui::TextUnformatted("Register before selected instruction");
    ImGui::SetNextItemWidth(-1);
    if (ImGui::BeginCombo("##register", valueOrigin_.selectedRegister.c_str())) {
        for (const auto& reg : choices)
            if (ImGui::Selectable(reg.c_str(), reg == valueOrigin_.selectedRegister)) valueOrigin_.selectedRegister = reg;
        ImGui::EndCombo();
    }
    if (ImGui::Button("Trace value")) requestValueOrigin(ctx, valueOrigin_.selectedRegister);
    ImGui::EndDisabled();
    if (valueOrigin_.pending) {
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            if (valueOrigin_.cancellation) valueOrigin_.cancellation->store(true, std::memory_order_release);
            valueOrigin_.pending = false; valueOrigin_.status = "Value-origin request cancelled.";
        }
    } else if (valueOrigin_.result) {
        ImGui::SameLine();
        if (ImGui::Button("Clear")) {
            valueOrigin_.result.reset(); valueOrigin_.highlighted.clear(); valueOrigin_.status.clear();
        }
    }
    if (!valueOrigin_.status.empty()) ImGui::TextWrapped("%s", valueOrigin_.status.c_str());
    const auto result = valueOrigin_.result;
    if (result) {
        ImGui::Text("Pinned: %s before 0x%llX", result->registerName.c_str(),
                    static_cast<unsigned long long>(result->instructionVA));
        ImGui::TextWrapped("Possible source instructions are highlighted in FILE Assembly. This is static dependency evidence, not an observed runtime value.");
        if (ImGui::SmallButton("Show selected instruction"))
            navigateToStaticView(result->instructionVA, DocumentView::Assembly);
        if (!result->sources.empty()) {
            ImGui::Text("Sources (%zu)", result->sources.size());
            ImGui::BeginChild("sources", ImVec2(0, 150.0f * theme::UiScale()), ImGuiChildFlags_Borders);
            ImGuiListClipper clip; clip.Begin(static_cast<int>(result->sources.size()));
            while (clip.Step()) for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                const auto& source = result->sources[static_cast<size_t>(i)];
                char address[32]; std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(source.va));
                ImGui::PushID(i);
                if (ImGui::Selectable(address)) navigateToStaticView(source.va, DocumentView::Assembly);
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s", source.instruction.c_str(), source.reason.c_str());
                ImGui::SameLine(); ImGui::TextUnformatted(source.instruction.c_str());
                ImGui::PopID();
            }
            ImGui::EndChild();
        }
        if (!result->boundaries.empty()) {
            ImGui::TextColored(theme::col::warn(), "Uncertainty / scope boundaries");
            ImGui::BeginChild("boundaries", ImVec2(0, 135.0f * theme::UiScale()), ImGuiChildFlags_Borders);
            ImGuiListClipper clip; clip.Begin(static_cast<int>(result->boundaries.size()));
            while (clip.Step()) for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                const auto& b = result->boundaries[static_cast<size_t>(i)];
                ImGui::PushID(i);
                char address[32]; std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(b.va));
                if (ImGui::Selectable(address)) navigateToStaticView(b.va, DocumentView::Assembly);
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", b.message.c_str());
                ImGui::SameLine(); ImGui::TextUnformatted(b.message.c_str());
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", b.message.c_str());
                ImGui::PopID();
            }
            ImGui::EndChild();
        }
    }
    ImGui::PopID();
}
} // namespace ds
