#include "BinaryViewTab.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"
#include <algorithm>
#include <cstdio>

namespace ds {
bool BinaryViewTab::stringTraceCurrent(AppContext& ctx) const {
    if (!ctx.staticBinary().loaded() || functionsDirty_ || patchRefresh_.pending() ||
        stringTrace_.imageSerial != investigationImageSerial_ ||
        stringTrace_.imageRevision != ctx.staticBinary().imageRevision() ||
        stringTrace_.epoch != ctx.staticAnalysis().epoch() ||
        stringTrace_.decoder != ctx.staticDecoderConfig()) return false;
    if (!stringTrace_.waiting && stringTrace_.functionsGeneration != functionsGen_) return false;
    if (stringTrace_.sourceLive) {
        uint64_t mapped = 0;
        if (!frameSnap_ || frameSnap_->pid != stringTrace_.pid ||
            frameSnap_->sessionGeneration != stringTrace_.session ||
            !ctx.debug.memorySessionMatches({stringTrace_.pid, stringTrace_.session}) ||
            !exactLiveToStaticVA(ctx, stringTrace_.sourceVA, mapped) || mapped != stringTrace_.fileVA)
            return false;
    }
    const auto& cache = ctx.staticAnalysisCache();
    return stringTrace_.waiting || (cache.matches(ctx.staticBinary(), stringTrace_.epoch) && cache.xrefs &&
        cache.xrefs == stringTrace_.xrefs && xrefIndexSig_ == xrefSig(ctx) &&
        (!cache.codeData || cache.xrefs->classificationScopeDigest == cache.codeData->scopeDigest));
}

void BinaryViewTab::requestStringActionTrace(AppContext& ctx, uint64_t va, const std::string& text, bool live) {
    // Own the arguments before retiring state: Retry can pass its retained text.
    const std::string selectedText = text;
    if (stringTrace_.cancellation) stringTrace_.cancellation->store(true, std::memory_order_release);
    const uint64_t nextId = stringTrace_.requestId + 1;
    stringTrace_ = {};
    stringTrace_.requestId = nextId ? nextId : 1;
    stringTrace_.open = stringTrace_.focus = true;
    stringTrace_.sourceVA = va; stringTrace_.fileVA = va;
    stringTrace_.sourceLive = live; stringTrace_.text = selectedText;
    stringTrace_.imageSerial = investigationImageSerial_;
    stringTrace_.imageRevision = ctx.staticBinary().imageRevision();
    if (live && frameSnap_) {
        stringTrace_.pid = frameSnap_->pid; stringTrace_.session = frameSnap_->sessionGeneration;
    }
    if (!ctx.staticBinary().loaded() || !ArchIsX86_32Or64(ctx.staticArch())) {
        stringTrace_.status = "Load or analyze the matching x86/x64 module, then trace its string again."; return;
    }
    if (functionsDirty_ || patchRefresh_.pending()) {
        stringTrace_.status = "Analysis is refreshing after a code change. Retry when it finishes."; return;
    }
    if (live) {
        if (!frameSnap_ || !exactLiveToStaticVA(ctx, va, stringTrace_.fileVA)) {
            stringTrace_.status = "This LIVE string has no verified mapping to the active analyzed image. Open its matching module, or use Find references (where used) to search live memory.";
            return;
        }
        stringTrace_.pid = frameSnap_->pid; stringTrace_.session = frameSnap_->sessionGeneration;
    }
    stringTrace_.epoch = ctx.staticAnalysis().epoch();
    stringTrace_.decoder = ctx.staticDecoderConfig();
    stringTrace_.cancellation = std::make_shared<std::atomic<bool>>(false);
    stringTrace_.waiting = true;
    stringTrace_.status = "Preparing function and string-reference evidence...";
    const auto& cache = ctx.staticAnalysisCache();
    uint32_t needed = 0;
    if (!cache.matches(ctx.staticBinary(), stringTrace_.epoch) || !cache.functions) needed |= K_Funcs | K_Xref;
    if (!cache.matches(ctx.staticBinary(), stringTrace_.epoch) || !cache.xrefs ||
        xrefIndexSig_ != xrefSig(ctx) ||
        (cache.codeData && cache.xrefs->classificationScopeDigest != cache.codeData->scopeDigest)) needed |= K_Xref;
    if (needed) queueStringActionDependencies(ctx, needed);
    advanceStringActionTrace(ctx);
}

void BinaryViewTab::advanceStringActionTrace(AppContext& ctx) {
    if (!(stringTrace_.waiting || stringTrace_.pending || stringTrace_.result)) return;
    if (!stringTraceCurrent(ctx)) {
        if (stringTrace_.cancellation) stringTrace_.cancellation->store(true, std::memory_order_release);
        stringTrace_.waiting = stringTrace_.pending = false;
        stringTrace_.result.reset(); stringTrace_.xrefs.reset();
        stringTrace_.status = "Trace retired because its image, analysis, or live session changed. Retry to refresh.";
        return;
    }
    if (stringTrace_.waiting) {
        const auto& cache = ctx.staticAnalysisCache();
        if (cache.matches(ctx.staticBinary(), stringTrace_.epoch) && cache.functions && cache.xrefs &&
            xrefIndexSig_ == xrefSig(ctx) &&
            (!cache.codeData || cache.xrefs->classificationScopeDigest == cache.codeData->scopeDigest)) {
            auto request = std::make_shared<StringActionTraceRequest>();
            request->requestId = stringTrace_.requestId;
            request->stringVA = stringTrace_.fileVA;
            request->stringText = stringTrace_.text;
            request->xrefs = cache.xrefs;
            request->cancellation = stringTrace_.cancellation;
            stringTrace_.xrefs = cache.xrefs;
            stringTrace_.functionsGeneration = functionsGen_;
            stringTrace_.waiting = false; stringTrace_.pending = true;
            stringTrace_.idleFrames = 0;
            stringTrace_.status = "Following string references and nearby function calls...";
            ctx.staticAnalysis().requestStringActionTrace(&ctx.staticBinary(), ctx.staticDecoderConfig(),
                stringTrace_.epoch, std::move(request), cache.functions);
            return;
        }
    }
    const uint32_t work = stringTrace_.waiting ? (K_Funcs | K_Xref) : K_StringActionTrace;
    if (ctx.staticAnalysis().pendingKinds() & work) stringTrace_.idleFrames = 0;
    else if ((stringTrace_.waiting || stringTrace_.pending) && ++stringTrace_.idleFrames > 2) {
        stringTrace_.waiting = stringTrace_.pending = false;
        stringTrace_.status = "Analysis ended without a current result. Retry to rebuild the evidence.";
    }
}

void BinaryViewTab::adoptStringActionTraceResult(AppContext& ctx, const AnalysisResult& result) {
    if (!(result.kinds & K_StringActionTrace) || !stringTrace_.pending ||
        result.stringActionTraceRequestId != stringTrace_.requestId ||
        result.epoch != stringTrace_.epoch || !stringTraceCurrent(ctx)) return;
    stringTrace_.pending = false;
    stringTrace_.result = result.stringActionTrace;
    stringTrace_.status = result.failureValid ? result.failure : result.stringActionTrace
        ? result.stringActionTrace->status : "No trace result was produced. Retry to refresh.";
}

void BinaryViewTab::renderStringActionTrace(AppContext& ctx) {
    advanceStringActionTrace(ctx);
    if (!stringTrace_.open) return;
    const float scale = theme::UiScale();
    ImGui::SetNextWindowSize(ImVec2(780 * scale, 580 * scale), ImGuiCond_FirstUseEver);
    if (stringTrace_.focus) { ImGui::SetNextWindowFocus(); stringTrace_.focus = false; }
    if (ImGui::Begin("String action trace", &stringTrace_.open)) {
        ui::PanelHeader("From string to value change", "FILE analysis");
        ImGui::TextWrapped("\"%s\"", stringTrace_.text.c_str());
        ImGui::TextDisabled("%s 0x%llX", stringTrace_.sourceLive ? "LIVE string" : "FILE string",
            static_cast<unsigned long long>(stringTrace_.sourceVA));
        ImGui::TextWrapped("Follow a message to nearby arithmetic and memory writes. Results are candidates; a message alone does not prove which game value changed.");
        if (stringTrace_.waiting || stringTrace_.pending) {
            if (ImGui::Button("Cancel")) {
                if (stringTrace_.cancellation) stringTrace_.cancellation->store(true, std::memory_order_release);
                stringTrace_.waiting = stringTrace_.pending = false;
                stringTrace_.status = "String action trace cancelled.";
            }
        } else {
            const bool sameSource = stringTrace_.imageSerial == investigationImageSerial_ &&
                stringTrace_.imageRevision == ctx.staticBinary().imageRevision() &&
                (!stringTrace_.sourceLive || (frameSnap_ && frameSnap_->pid == stringTrace_.pid &&
                    frameSnap_->sessionGeneration == stringTrace_.session &&
                    ctx.debug.memorySessionMatches({stringTrace_.pid, stringTrace_.session})));
            ImGui::BeginDisabled(!sameSource);
            if (ImGui::Button("Retry trace") && sameSource)
                requestStringActionTrace(ctx, stringTrace_.sourceVA, stringTrace_.text, stringTrace_.sourceLive);
            ImGui::EndDisabled();
            if (!sameSource) ImGui::TextWrapped("Select the string again in the current image or live session to start a new trace.");
        }
        ImGui::TextWrapped("%s", stringTrace_.status.c_str());
        ImGui::TextDisabled("Scope: up to 48 functions, 2 direct-call hops, 96 instruction edges per anchor.");
        const auto result = stringTrace_.result;
        if (result) {
            if (!result->complete) ImGui::TextColored(theme::col::warn(), "Partial search — see scope below");
            const auto& candidates = result->candidates;
            if (ui::BeginDataTable("string_action_candidates", 3,
                ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                ImVec2(0, 170 * scale))) {
                ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthFixed, 145 * scale);
                ImGui::TableSetupColumn("Candidate change");
                ImGui::TableSetupColumn("Evidence", ImGuiTableColumnFlags_WidthFixed, 100 * scale);
                ImGui::TableSetupScrollFreeze(0, 1); ImGui::TableHeadersRow();
                ImGuiListClipper clip; clip.Begin(static_cast<int>(candidates.size()));
                while (clip.Step()) for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                    const auto& candidate = candidates[static_cast<size_t>(i)];
                    ImGui::PushID(i); ImGui::TableNextRow(); ImGui::TableSetColumnIndex(0);
                    char address[40]; std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(candidate.instructionVA));
                    if (ImGui::Selectable(address, stringTrace_.selected == i, ImGuiSelectableFlags_SpanAllColumns)) stringTrace_.selected = i;
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s", candidate.instruction.c_str(), candidate.evidence.c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(candidate.action.c_str());
                    ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(candidate.confidence >= 0.75f ? "Stronger" : "Possible");
                    ImGui::PopID();
                }
                ui::EndDataTable();
            }
            if (!candidates.empty()) {
                stringTrace_.selected = std::clamp(stringTrace_.selected, 0, static_cast<int>(candidates.size()) - 1);
                const auto& candidate = candidates[static_cast<size_t>(stringTrace_.selected)];
                ImGui::TextWrapped("%s", candidate.instruction.c_str());
                ImGui::TextWrapped("%s", candidate.evidence.c_str());
                if (!candidate.suggestedName.empty())
                    ImGui::TextColored(theme::col::warn(), "Name hint: %s", candidate.suggestedName.c_str());
                if (ImGui::Button("Show instruction")) navigateToStaticView(candidate.instructionVA, DocumentView::Assembly);
                ImGui::SameLine();
                if (ImGui::Button("Show function")) navigateToStaticView(candidate.functionVA, DocumentView::Pseudocode);
                uint64_t runtime = 0;
                const bool liveReady = frameSnap_ && ctx.debuggerStaticRuntimeVA(*frameSnap_, candidate.instructionVA, runtime);
                ImGui::SameLine(); ImGui::BeginDisabled(!liveReady);
                if (ImGui::Button("Open Live Assembly")) { mainView_ = 4; liveNavigate(runtime); }
                ImGui::EndDisabled();
                if (!liveReady && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                    ImGui::SetTooltip("Requires a verified matching module in the attached process.");
                ImGui::TextDisabled("Evidence path (FILE addresses)");
                for (size_t i = 0; i < candidate.path.size(); ++i) {
                    const auto& step = candidate.path[i];
                    ImGui::PushID(static_cast<int>(i));
                    char address[40]; std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(step.va));
                    if (ImGui::SmallButton(address)) navigateToStaticView(step.va, DocumentView::Assembly);
                    ImGui::SameLine(); ImGui::TextWrapped("%s", step.label.c_str()); ImGui::PopID();
                }
            }
            if (ImGui::CollapsingHeader("Search scope and limitations"))
                for (const auto& limitation : result->limitations) ImGui::BulletText("%s", limitation.c_str());
        }
    }
    ImGui::End();
    if (!stringTrace_.open && (stringTrace_.pending || stringTrace_.waiting)) {
        if (stringTrace_.cancellation) stringTrace_.cancellation->store(true, std::memory_order_release);
        stringTrace_.pending = stringTrace_.waiting = false;
    }
}
} // namespace ds
