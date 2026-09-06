#include "BinaryViewTab.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"

#include <algorithm>
#include <cstdio>

namespace ds {

void BinaryViewTab::renderOverview(AppContext& ctx) {
    const BinaryFile& binary = ctx.staticBinary();
    if (!binary.loaded()) return;
    const auto& cache = ctx.staticAnalysisCache();
    const uint64_t epoch = ctx.staticAnalysis().epoch();
    const bool current = cache.matches(binary, epoch);
    const auto functions = current ? cache.functions : nullptr;
    const auto strings = current ? cache.strings : nullptr;
    const auto xrefs = current ? cache.xrefs : nullptr;
    const auto codeData = current ? cache.codeData : nullptr;
    const auto triage = current ? cache.crackmeTriage : nullptr;
    if (overviewImageSerial_ != investigationImageSerial_ ||
        overviewImageRevision_ != binary.imageRevision() ||
        overviewEpoch_ != epoch || overviewFunctions_ != functions) {
        overview_ = BuildBinaryOverview(binary, functions.get(), ctx.staticArch());
        overviewImageSerial_ = investigationImageSerial_;
        overviewImageRevision_ = binary.imageRevision();
        overviewEpoch_ = epoch;
        overviewFunctions_ = functions;
    }

    const float scale = theme::UiScale();
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8 * scale, 7 * scale));
    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(8 * scale, 7 * scale));
    ImGui::PushTextWrapPos(0.0f);
    const std::string& path = binary.path();
    const size_t slash = path.find_last_of("/\\");
    const char* name = slash == std::string::npos ? path.c_str() : path.c_str() + slash + 1;
    ImGui::TextColored(theme::col::accent(), "%s", name);
    ImGui::TextWrapped("Understand this image, choose a starting point, then follow its references into code.");
    ImGui::TextDisabled("%s | %s | %s | %zu bytes", binary.formatName(),
                        ArchName(ctx.staticArch()),
                        binary.isMappedImage() ? "Memory snapshot" : "File image",
                        binary.bytes().size());
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", path.c_str());
    ImGui::TextDisabled("%zu sections | %zu imports | %zu exports / symbols",
                        binary.sections().size(), binary.imports().size(), binary.exports().size());

    auto sideAction = [&](int which) {
        sideAdvancedMode_ = false;
        overviewSideRequest_ = which;
    };
    auto importsAction = [&] {
        lowerAdvancedMode_ = false;
        lowerDockCollapsed_ = false;
        overviewImportsRequest_ = true;
    };
    auto wrapButton = [&](const char* label) {
        const float width = ImGui::CalcTextSize(label).x + ImGui::GetStyle().FramePadding.x * 2;
        const float right = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
        if (ImGui::GetItemRectMax().x + width + ImGui::GetStyle().ItemSpacing.x <= right)
            ImGui::SameLine();
    };
    if (ImGui::Button("Browse functions")) sideAction(1);
    wrapButton("Find strings");
    if (ImGui::Button("Find strings")) sideAction(2);
    wrapButton("Inspect imports");
    if (ImGui::Button("Inspect imports")) importsAction();
    wrapButton("Bookmarks");
    if (ImGui::Button("Bookmarks")) sideAction(3);
    ImGui::TextDisabled("Ctrl+K searches across the investigation. X on an instruction opens references.");

    if (ImGui::CollapsingHeader("Starting points", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::PushID("overview_starts");
        if (staticCursorValid_) {
            size_t available = 0;
            if (binary.ptrFromVA(staticCursorVA_, available) && available) {
                if (ImGui::SmallButton("Open current address")) {
                    mainView_ = 0;
                    navigateTo(staticCursorVA_);
                }
                ImGui::SameLine();
                ImGui::TextDisabled("0x%llX", static_cast<unsigned long long>(staticCursorVA_));
            }
        }
        if (overview_.entryDeclared && !overview_.entryMapped)
            ImGui::TextColored(theme::col::warn(), "The declared entry has no file-backed destination.");
        else if (!overview_.entryDeclared)
            ImGui::TextDisabled("This image has no declared entry point. Symbols and executable sections can still be explored.");

        const bool canDecompile = ArchSupportsDecompiler(ctx.staticArch());
        const size_t shown = overviewMoreLeads_ ? overview_.leads.size() : std::min<size_t>(4, overview_.leads.size());
        for (size_t i = 0; i < shown; ++i) {
            const auto& lead = overview_.leads[i];
            ImGui::PushID(static_cast<int>(i));
            ImGui::Separator();
            ImGui::TextColored(lead.inferred ? theme::col::warn() : theme::col::accent(),
                               "%s", lead.label.c_str());
            ImGui::TextDisabled("0x%llX%s", static_cast<unsigned long long>(lead.va),
                                lead.inferred ? " | inferred candidate" : "");
            ImGui::TextWrapped("%s", lead.evidence.c_str());
            if (ImGui::SmallButton(lead.code ? "Assembly" : "Hex")) {
                mainView_ = lead.code ? 0 : 2;
                hexLastScrollValid_ = false;
                navigateTo(lead.va);
            }
            if (lead.code && canDecompile) {
                ImGui::SameLine();
                if (ImGui::SmallButton("Pseudocode")) {
                    mainView_ = 1;
                    navigateTo(lead.va);
                }
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("References")) startXrefSearch(ctx, lead.va, false);
            ImGui::PopID();
        }
        if (overview_.leads.empty())
            ImGui::TextWrapped("No mapped starting point is available. Inspect Hex or Imports, or review the raw mapping and architecture.");
        if (overview_.candidatesLimited)
            ImGui::TextDisabled("Showing a bounded selection. Browse Functions and Exports / Symbols for more.");
        if (overview_.leads.size() > 4) ImGui::Checkbox("More starting points", &overviewMoreLeads_);
        ImGui::PopID();
    }

    if (ImGui::CollapsingHeader("Analysis coverage", ImGuiTreeNodeFlags_DefaultOpen)) {
        const bool busy = ctx.staticAnalysis().bulkPending() || functionsDirty_;
        if (busy) {
            ImGui::TextColored(theme::col::accent(), "Analysis is running; available results can be explored now.");
        }
        const char* unavailable = busy ? "Result not available yet" : "Not available - use Analyze";
        if (ImGui::BeginTable("overview_coverage", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Analysis", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableSetupColumn("Coverage", ImGuiTableColumnFlags_WidthStretch, 2.0f);
            ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted("Function candidates");
            ImGui::TableNextColumn();
            if (functions) ImGui::Text("%zu discovered; boundaries may be inferred", functions->size());
            else ImGui::TextDisabled("%s", unavailable);
            ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted("File strings");
            ImGui::TableNextColumn();
            if (strings) ImGui::Text("%zu%s found", strings->size(), cache.stringsTruncated ? "+ (scan limited)" : "");
            else ImGui::TextDisabled("%s", unavailable);
            ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::TextUnformatted("Cross-references");
            ImGui::TableNextColumn();
            if (xrefs) {
                ImGui::Text("%zu referenced addresses%s", xrefs->toTarget.size(), xrefs->complete ? "" : " (partial)");
                if (!xrefs->complete) ImGui::TextColored(theme::col::warn(), "%s", xrefs->incompleteReason());
            } else ImGui::TextDisabled("%s", unavailable);
            ImGui::EndTable();
        }
        if (codeData && codeData->imageRevision == binary.imageRevision()) {
            const auto& stats = codeData->stats;
            ImGui::TextWrapped("Executable-byte classification: %llu code, %llu data, %llu unknown out of %llu bytes.",
                static_cast<unsigned long long>(stats.codeBytes), static_cast<unsigned long long>(stats.dataBytes),
                static_cast<unsigned long long>(stats.unknownBytes), static_cast<unsigned long long>(stats.executableBytes));
            if (codeData->truncated) ImGui::TextColored(theme::col::warn(), "Partial classification: %s", codeData->truncationReason.c_str());
        }
        ImGui::BeginDisabled(busy);
        if (ImGui::SmallButton("Analyze")) analyzeFunctions(ctx);
        ImGui::EndDisabled();
        ImGui::TextDisabled("Counts describe available static evidence. Empty or partial results do not prove a behavior is absent.");
    }

    if (ImGui::CollapsingHeader("Follow evidence", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::PushID("overview_evidence");
        ImGui::TextWrapped("Strings reveal messages and identifiers. Imports reveal dependencies; references show where the image uses them.");
        // A bounded preview of loader records; xref lookup is constant-time and
        // does not decode, scan the image, or total the entire xref graph.
        const auto& imports = binary.imports();
        const size_t previewCount = std::min<size_t>(imports.size(), 6);
        for (size_t i = 0; i < previewCount; ++i) {
            const auto& import = imports[i];
            ImGui::PushID(static_cast<int>(i));
            ImGui::TextWrapped("%.120s%s%.160s", import.dll.c_str(), import.dll.empty() ? "" : "!", import.name.c_str());
            const auto* sources = xrefs && import.addressKnown ? xrefs->sources(import.iatVA) : nullptr;
            if (sources) ImGui::TextDisabled("%zu static reference(s)%s", sources->size(), xrefs->complete ? "" : " in a partial index");
            ImGui::BeginDisabled(!import.addressKnown);
            if (ImGui::SmallButton("References")) startXrefSearch(ctx, import.iatVA, false);
            ImGui::EndDisabled();
            if (!import.addressKnown) {
                ImGui::SameLine(); ImGui::TextDisabled("Address unresolved");
            }
            ImGui::PopID();
        }
        if (imports.empty()) ImGui::TextDisabled("No imports were recorded by the loader.");
        if (imports.size() > previewCount && ImGui::SmallButton("Browse all imports")) importsAction();

        const auto& runtime = ctx.staticRuntimeInfo();
        if (runtime.wrapperLikely) {
            ImGui::Separator();
            ImGui::TextColored(theme::col::warn(), "Possible runtime wrapper: %s", runtime.wrapperRuntime.c_str());
            ImGui::TextWrapped("%s", runtime.wrapperDetail.c_str());
        }
        if (ImGui::Button("Binary capabilities")) ctx.requestedTab = "Binary Tech";
        if (triage) {
            if (!triage->endpoints.empty() || !triage->apis.empty()) {
                wrapButton("Network trail");
                if (ImGui::Button("Network trail")) ctx.openCrackmeTriage(TriageWorkspaceView::NetworkTrail);
            }
            if (!triage->authorization.stateOperations.empty() ||
                !triage->authorization.flows.empty() || !triage->authorizationTrail.predicates.empty()) {
                wrapButton("Authorization trail");
                if (ImGui::Button("Authorization trail")) ctx.openCrackmeTriage(TriageWorkspaceView::Authorization);
            }
            if (!triage->completeness.complete)
                ImGui::TextColored(theme::col::warn(), "Partial trail analysis: %s", triage->completeness.reason.c_str());
        }
        ImGui::PopID();
    }
    ImGui::PopTextWrapPos();
    ImGui::PopStyleVar(2);
}

} // namespace ds
