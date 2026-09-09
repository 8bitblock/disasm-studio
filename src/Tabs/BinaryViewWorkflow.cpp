#include "BinaryViewTab.h"
#include "../Core/FunctionFilter.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "../Ui/Fonts.h"
#include "imgui.h"
#include "imgui_internal.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace ds {

void BinaryViewTab::refreshFunctionFilter(bool lower) {
    const char* query = lower ? funcTabFilter_ : fnFilter_;
    char* previous = lower ? funcTabFilterLast_ : fnFilterLast_;
    const size_t capacity = lower ? sizeof(funcTabFilterLast_) : sizeof(fnFilterLast_);
    auto& generation = lower ? funcTabVisSig_ : fnVisSig_;
    auto& renameGeneration = lower ? funcTabVisNamesGen_ : fnVisNamesGen_;
    auto& visible = lower ? funcTabVisible_ : fnVisible_;
    // Exact revisions also catch replacement of interior functions when the
    // count and first/last addresses are unchanged.
    if (generation == functionsGen_ && renameGeneration == namesGen_ &&
        std::strcmp(query, previous) == 0) return;
    const FunctionFilter filter(query);
    visible.clear();
    visible.reserve(functions_.size());
    for (size_t i = 0; i < functions_.size(); ++i) {
        const Func& function = functions_[i];
        if (!lower && fnCategory_) {
            const auto named = names_.find(function.address);
            const bool user = named != names_.end() && !named->second.empty();
            const bool guessed = function.guessed && !user;
            const bool generic = !user && !guessed && function.name.rfind("sub_", 0) == 0;
            const int category = user ? 1 : guessed ? 3 : generic ? 4 : 2;
            if (category != fnCategory_) continue;
        }
        if (!filter.empty()) {
            const auto renamed = names_.find(function.address);
            const std::string_view displayName = renamed != names_.end() && !renamed->second.empty()
                ? std::string_view(renamed->second) : std::string_view(function.name);
            if (!filter.matches(displayName, function.name, function.address)) continue;
        }
        visible.push_back(static_cast<int>(i));
    }
    std::snprintf(previous, capacity, "%s", query);
    generation = functionsGen_;
    renameGeneration = namesGen_;
}

void BinaryViewTab::renderFunctionDestinations(AppContext& ctx, uint64_t address) {
    if (ImGui::MenuItem("Open in Assembly"))
        navigateToStaticView(address, DocumentView::Assembly);
    if (ImGui::MenuItem("Open in Pseudocode", nullptr, false,
                        ArchSupportsDecompiler(ctx.staticArch())))
        navigateToStaticView(address, DocumentView::Pseudocode);
    if (ImGui::MenuItem("Open in Control-flow graph"))
        navigateToStaticView(address, DocumentView::Graph);
    if (ImGui::MenuItem("References to function")) startXrefSearch(ctx, address, false);
    ImGui::Separator();
}

void BinaryViewTab::selectRepresentation(AppContext& ctx, int view) {
    if (view < 0 || view >= 8) return;
    if (view == 1 && !ArchSupportsDecompiler(ctx.staticArch())) view = 0;
    if (view == 4 && (!frameSnap_ || !frameSnap_->attached())) return;
    if (view == 4 && mainView_ != 4) {
        focusRegistersTab_ = true;
        lowerAdvancedMode_ = false;
        lowerDockCollapsed_ = false;
    }
    if (mainView_ >= 0 && mainView_ < 8 && viewPins_[mainView_].valid && navigation_)
        viewPins_[mainView_] = navigation_->current();
    mainView_ = view;
    const DocumentLocation pin = viewPins_[view];
    if (pin.valid && pin.addressSpace == DocumentAddressSpace::Live && frameSnap_) {
        const DebugTargetIdentity current{frameSnap_->pid, frameSnap_->sessionGeneration};
        if (DebugTargetIdentityMatches(current, pin.target)) {
            restoreNavigationLocation(pin);
            if (navigation_) navigation_->replaceCurrent(pin);
        }
        else viewPins_[view] = {};
    } else if (pin.valid && pin.addressSpace == DocumentAddressSpace::File) {
        restoreNavigationLocation(pin);
        if (navigation_) navigation_->replaceCurrent(pin);
    } else if (pin.valid && pin.addressSpace == DocumentAddressSpace::FileOffset) {
        restoreNavigationLocation(pin);
        if (navigation_) navigation_->replaceCurrent(pin);
    }
    if (mainView_ == 4) restoreLiveCursor(*frameSnap_);
    else restoreStaticCursor(ctx);
    updateNavigationRepresentation();
}

void BinaryViewTab::applyWorkflow(AppContext& ctx, int preset) {
    if (preset < 0 || preset > 3) return;
    workflowPreset_ = preset;
    lowerDockCollapsed_ = false;
    sideAdvancedMode_ = false;
    overviewSideRequest_ = 1;
    if (preset == 0) {
        selectRepresentation(ctx, 0);
        lowerAdvancedMode_ = true;
        ctx.openCrackmeTriage();
    } else if (preset == 1) {
        lowerAdvancedMode_ = false;
        focusRegistersTab_ = true;
        if (frameSnap_ && frameSnap_->attached()) selectRepresentation(ctx, 4);
        else ctx.requestedTab = "Communications";
    } else if (preset == 2) {
        if (frameSnap_ && frameSnap_->attached()) ctx.requestedTab = "Memory Tools";
        else {
            selectRepresentation(ctx, 2);
            lowerAdvancedMode_ = true;
            focusTypesTab_ = true;
        }
    } else ctx.requestedTab = "Binary Diff";
}

void BinaryViewTab::renderWorkflowContext(AppContext& ctx, bool compactMenu) {
    const float scale = theme::UiScale();
    if (viewPinsImage_ != investigationImageSerial_) {
        for (auto& pin : viewPins_) pin = {};
        viewPinsImage_ = investigationImageSerial_;
    }
    if (ctx.requestedWorkflow >= 0) {
        const int preset = ctx.requestedWorkflow;
        ctx.requestedWorkflow = -1;
        applyWorkflow(ctx, preset);
    }
    if (ctx.requestedTypeWorkbench) {
        ctx.requestedTypeWorkbench = false;
        focusTypesTab_ = lowerAdvancedMode_ = true;
        lowerDockCollapsed_ = false;
    }
    if (compactMenu) {
        if (ImGui::SmallButton("Workspace###binary_workspace"))
            ImGui::OpenPopup("binary_workspace_tools");
        ui::ItemTooltip("Presets, navigator tools, analysis queue, registers and location pinning.");
        const ImVec2 viewportSize = ImGui::GetMainViewport()->WorkSize;
        const ImVec2 popupMax(std::max(1.0f, viewportSize.x - 16.0f * scale),
                             std::max(1.0f, viewportSize.y - 16.0f * scale));
        ImGui::SetNextWindowSizeConstraints(ImVec2(0, 0), popupMax);
        ImGui::SetNextWindowSize(ImVec2(std::min(560.0f * scale, popupMax.x), 0), ImGuiCond_Appearing);
        if (!ImGui::BeginPopup("binary_workspace_tools")) return;
    }
    const char* labels[] = {"Analyze", "Debug", "Memory", "Compare"};
    const char* hints[] = {
        "Assembly, function navigator, and crackme triage",
        "Live assembly and registers, or choose a process to attach",
        "Live memory tools when attached; FILE hex and types otherwise",
        "Compare baseline and candidate binaries"};
    const auto nextSmallButton = [](const char* label) {
        ui::SameLineIfFits(ImGui::CalcTextSize(label).x + ImGui::GetStyle().FramePadding.x * 2.0f);
    };
    const bool compact = ImGui::GetContentRegionAvail().x < 720.0f * scale;
    if (compact) {
        ImGui::SetNextItemWidth(130.0f * scale);
        int chosen = workflowPreset_;
        if (ImGui::Combo("##workflow_preset", &chosen, labels, 4)) applyWorkflow(ctx, chosen);
        ui::ItemTooltip(hints[workflowPreset_]);
    }
    for (int i = 0; !compact && i < 4; ++i) {
        ui::PushMono();
        const float pillWidth = ImGui::CalcTextSize(labels[i]).x +
            (ImGui::GetStyle().FramePadding.x + 2.0f * scale) * 2.0f;
        ui::PopMono();
        if (i) ui::SameLineIfFits(pillWidth);
        const ImVec4 accent = theme::col::accent();
        if (ui::Pill(labels[i], labels[i], i == workflowPreset_ ? &accent : nullptr, hints[i])) applyWorkflow(ctx, i);
    }
    const bool canPin = navigation_ && navigation_->current().valid && mainView_ >= 0 && mainView_ <= 5;
    const bool pinned = mainView_ >= 0 && mainView_ < 8 && viewPins_[mainView_].valid;
    nextSmallButton("Workspace");
    if (ImGui::SmallButton("Workspace")) ImGui::OpenPopup("workflow_tools");
    ui::ItemTooltip("Analysis destinations and per-view location pinning.");
    if (ImGui::BeginPopup("workflow_tools")) {
        if (ImGui::MenuItem("Activation trail")) {
            lowerAdvancedMode_ = true;
            lowerDockCollapsed_ = false;
            ctx.openCrackmeTriage(TriageWorkspaceView::Authorization);
        }
        if (ImGui::MenuItem("Types")) {
            focusTypesTab_ = lowerAdvancedMode_ = true;
            lowerDockCollapsed_ = false;
        }
        ImGui::Separator();
        if (ImGui::MenuItem(pinned ? "Unpin view" : "Pin view", nullptr, pinned, canPin))
            viewPins_[mainView_] = pinned ? DocumentLocation{} : navigation_->current();
        ui::ItemTooltip("A pinned representation retains its location when switching views. Unpinned FILE views share selection; LIVE keeps its own target location.");
        ImGui::EndPopup();
    }
    nextSmallButton("Registers");
    if (ImGui::SmallButton("Registers")) {
        focusRegistersTab_ = true;
        lowerAdvancedMode_ = false;
        lowerDockCollapsed_ = false;
    }
    ui::ItemTooltip("Show live registers. Double-click a value to edit while paused.");
    nextSmallButton(evidenceInspectorCollapsed_ && lowerDockCollapsed_ ? "Expand panes" : "Focus code");
    if (ImGui::SmallButton(evidenceInspectorCollapsed_ && lowerDockCollapsed_ ? "Expand panes" : "Focus code")) {
        const bool collapse = !(evidenceInspectorCollapsed_ && lowerDockCollapsed_);
        evidenceInspectorCollapsed_ = lowerDockCollapsed_ = collapse;
        analysisQueueCollapsed_ = collapse;
    }

    // Source and address retain their own space; long filenames/symbols may
    // shorten the context, but must never hide whether this is FILE or LIVE.
    std::string path = ctx.staticBinary().path();
    const size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos) path.erase(0, slash + 1);
    if (path.empty()) path = "Untitled";
    const DocumentLocation location = navigation_ ? navigation_->current() : DocumentLocation{};
    const bool live = location.valid ? location.addressSpace == DocumentAddressSpace::Live : cursorLive_;
    const bool offset = location.valid && location.addressSpace == DocumentAddressSpace::FileOffset;
    const uint64_t address = location.valid ? location.va : cursorVA_;
    const bool valid = location.valid || cursorValid_;
    const char* source = live ? "LIVE" : offset ? "FILE offset" : "FILE";
    std::string detail = path;
    uint64_t fileVA = address;
    const bool mapped = !offset && (!live || exactLiveToStaticVA(ctx, address, fileVA));
    if (live && frameSnap_) {
        for (const auto& module : frameSnap_->modules) {
            if (address >= module.base && address - module.base < module.size) {
                detail += " / " + module.name;
                break;
            }
        }
    } else if (mapped && valid) {
        for (const auto& section : ctx.staticBinary().sections()) {
            const uint64_t base = ctx.staticBinary().imageBase() + section.virtualAddress;
            if (fileVA >= base && fileVA - base < std::max(section.virtualSize, section.rawSize)) {
                detail += " / " + section.name;
                break;
            }
        }
    }
    if (valid && mapped) {
        if (const Func* function = funcContaining(fileVA); function && function->contains(fileVA)) {
            std::string name = annName(ctx, function->address);
            detail += " / " + (name.empty() ? function->name : name);
        }
    }
    char addressText[64];
    if (valid) std::snprintf(addressText, sizeof(addressText), "0x%llX%s",
        static_cast<unsigned long long>(address), pinned ? "  [pinned]" : "");
    else std::snprintf(addressText, sizeof(addressText), "Select a location");
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    const float width = std::max(1.0f, ImGui::GetContentRegionAvail().x);
    const float padding = 6.0f * scale;
    const float gap = 10.0f * scale;
    const float lineHeight = ImGui::GetTextLineHeight();
    const float sourcePadding = 4.0f * scale;
    const float sourceWidth = ImGui::CalcTextSize(source).x + sourcePadding * 2.0f;
    const float sourceHeight = lineHeight + 4.0f * scale;
    const float rightWidth = ImGui::CalcTextSize(addressText).x;
    // At exceptionally narrow widths keep the address on its own second line.
    const bool twoLines = width < sourceWidth + rightWidth + gap + padding * 2.0f;
    const float height = sourceHeight + (twoLines ? lineHeight + 3.0f * scale : 0.0f) + padding * 2.0f;
    ImGui::BeginDisabled(!valid);
    const bool copied = ImGui::InvisibleButton("##location_breadcrumb", ImVec2(width, height),
                                               ImGuiButtonFlags_EnableNav);
    ImGui::EndDisabled();
    const bool hovered = ImGui::IsItemHovered();
    const bool focused = ImGui::IsItemFocused();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(origin, ImVec2(origin.x + width, origin.y + height),
                        ImGui::GetColorU32(theme::col::chrome()), 3.0f * scale);
    draw->AddLine(ImVec2(origin.x, origin.y + height),
                  ImVec2(origin.x + width, origin.y + height),
                  ImGui::GetColorU32(theme::col::paneLine()), std::max(1.0f, std::round(scale)));
    if (hovered || focused) {
        ImVec4 hover = theme::col::accent(); hover.w = 0.04f;
        draw->AddRectFilled(origin, ImVec2(origin.x + width, origin.y + height),
                            ImGui::GetColorU32(hover), 3.0f * scale);
        if (focused) draw->AddRect(origin, ImVec2(origin.x + width, origin.y + height),
                                   ImGui::GetColorU32(theme::col::accent()), 3.0f * scale);
    }
    const ImVec2 textOrigin(origin.x + padding, origin.y + padding + 2.0f * scale);
    const float right = origin.x + width - padding;
    const float addressX = twoLines ? textOrigin.x : right - rightWidth;
    const float contextLeft = textOrigin.x + sourceWidth + gap;
    const float contextRight = twoLines ? right : addressX - gap;
    draw->PushClipRect(origin, ImVec2(origin.x + width, origin.y + height), true);
    const ImVec4 sourceTint = live ? theme::col::warn() : theme::col::accent();
    const ImU32 sourceColor = ImGui::GetColorU32(sourceTint);
    ImVec4 sourceFill = sourceTint; sourceFill.w = 0.12f;
    ImVec4 sourceBorder = sourceTint; sourceBorder.w = 0.30f;
    const ImVec2 sourceMin(textOrigin.x, origin.y + padding);
    const ImVec2 sourceMax(sourceMin.x + sourceWidth, sourceMin.y + sourceHeight);
    draw->AddRectFilled(sourceMin, sourceMax, ImGui::GetColorU32(sourceFill), sourceHeight * 0.5f);
    draw->AddRect(sourceMin, sourceMax, ImGui::GetColorU32(sourceBorder), sourceHeight * 0.5f);
    draw->AddText(ImVec2(textOrigin.x + sourcePadding, textOrigin.y), sourceColor, source);
    if (contextRight > contextLeft) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::col::secondaryText());
        ImGui::RenderTextEllipsis(draw, ImVec2(contextLeft, textOrigin.y),
            ImVec2(contextRight, textOrigin.y + lineHeight), contextRight, contextRight,
            detail.c_str(), detail.c_str() + detail.size(), nullptr);
        ImGui::PopStyleColor();
    }
    draw->AddText(ImVec2(addressX, twoLines ? sourceMax.y + 3.0f * scale : textOrigin.y),
                  sourceColor, addressText);
    draw->PopClipRect();
    const std::string hint = std::string(source) + " / " + detail + " / " + addressText +
        (valid ? "\nClick or focus and press Space to copy the location." : "");
    ui::ItemTooltip(hint.c_str());
    if (valid && copied) {
        char copy[64];
        std::snprintf(copy, sizeof(copy), "%s:0x%llX", live ? "LIVE" : offset ? "FILEOFF" : "FILE",
            static_cast<unsigned long long>(address));
        ImGui::SetClipboardText(copy);
        ui::Toast(ui::ToastKind::Success, std::string("Copied ") + copy);
    }
    if (compactMenu) ImGui::EndPopup();
}

} // namespace ds
