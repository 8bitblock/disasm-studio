#include "BinaryTechTab.h"
#include "../Core/BinaryFile.h"
#include "../Core/AlgoScan.h"
#include "../Ui/Fonts.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"
#include <algorithm>

namespace ds {

void BinaryTechTab::runTechScan(AppContext& ctx) {
    caps_ = ScanCapabilities(ctx.binary);   // imports + sections + structural byte patterns
    // Merge the dedicated algorithm/crypto recognizer (known constants + Base64 alphabets,
    // section-aware). Synchronous and extent-map-free here (nullptr xref/functions) - the
    // Binary View "Algorithms" tab shows the "referenced by" links; this is the flat list.
    for (auto& a : ScanAlgorithms(ctx.binary)) {
        Capability c;
        c.name = a.name; c.category = a.category; c.confidence = a.confidence;
        c.address = a.address; c.addresses = a.dataVAs; c.hitCount = a.dataVAs.size();
        c.detail = a.detail + (a.section.empty() ? std::string() : "  [" + a.section + "]");
        c.analyzer = "AlgoScan";
        caps_.push_back(std::move(c));
    }
    std::sort(caps_.begin(), caps_.end(),
              [](const Capability& x, const Capability& y) { return x.confidence > y.confidence; });
    selected_ = caps_.empty() ? -1 : 0;
    scanned_ = true;
}

// Is the section containing `va` executable? (controls disasm vs hex preview)
static bool vaIsExecutable(const BinaryFile& bin, uint64_t va) {
    uint64_t rva = va >= bin.imageBase() ? va - bin.imageBase() : va;
    for (const auto& s : bin.sections())
        if (rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize) return s.executable;
    return false;
}

void BinaryTechTab::render(AppContext& ctx) {
    // No binary: a hero card with the open action instead of a disabled form.
    if (!ctx.binary.loaded()) {
        if (ui::EmptyState(DS_ICON_SHIELD, "No binary loaded",
                           "Open a binary to detect capabilities from imports, section names, and byte patterns.",
                           "Open Binary..."))
            ctx.openBinaryDialog();
        return;
    }

    if (ui::ToolbarIconButton(DS_ICON_SHIELD, "Run Tech Scan",
                              "Detect capabilities and techniques from imports, section names, and byte patterns"))
        runTechScan(ctx);
    ImGui::SameLine();
    ui::SearchBox("##techfilter", "filter category...", filter_, sizeof(filter_), 200.0f * theme::UiScale());
    ImGui::SameLine();
    if (scanned_) ImGui::TextDisabled("%d capabilit%s", (int)caps_.size(), caps_.size() == 1 ? "y" : "ies");
    else          ImGui::TextDisabled("not scanned");
    ImGui::Separator();

    if (!scanned_) {
        if (ui::EmptyState(DS_ICON_SHIELD, "Not scanned yet",
                           "Run the tech scan to map this binary's capabilities (network, crypto, injection, anti-debug, ...).",
                           "Run Tech Scan"))
            runTechScan(ctx);
        return;
    }
    if (caps_.empty()) {
        ui::EmptyState(DS_ICON_CHECK, "No notable capabilities detected",
                       "No flagged imports, packer sections, or known byte patterns in this binary.");
        return;
    }

    // Left: capabilities list. Right: detail + code/hex preview for the selection.
    ImGui::BeginChild("caplist", ImVec2(380, 0), ImGuiChildFlags_Borders);
    if (ImGui::BeginTable("caps", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Capability");
        ImGui::TableSetupColumn("Cat", ImGuiTableColumnFlags_WidthFixed, 84);
        ImGui::TableSetupColumn("Conf", ImGuiTableColumnFlags_WidthFixed, 46);
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)caps_.size(); ++i) {
            auto& c = caps_[i];
            if (filter_[0] && c.category.find(filter_) == std::string::npos) continue;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(c.name.c_str(), selected_ == i, ImGuiSelectableFlags_SpanAllColumns))
                selected_ = i;
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && c.address)
                ctx.gotoAddress(c.address);
            ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", c.category.c_str());
            ImGui::TableSetColumnIndex(2);
            ImVec4 col = c.confidence > 0.85f ? theme::col::good()
                       : c.confidence > 0.65f ? theme::col::warn()
                                              : theme::col::bad();
            ImGui::TextColored(col, "%.0f%%", c.confidence * 100.0f);
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("capdetail", ImVec2(0, 0), ImGuiChildFlags_Borders);
    if (selected_ >= 0 && selected_ < (int)caps_.size()) {
        auto& c = caps_[selected_];
        ImGui::TextColored(theme::col::accent(), "%s", c.name.c_str());
        ImGui::TextDisabled("Category: %s   Confidence: %.0f%%   Address: 0x%llX",
                            c.category.c_str(), c.confidence * 100.0f, (unsigned long long)c.address);
        if (c.address) {
            ImGui::SameLine();
            if (ImGui::SmallButton("View in disassembly")) ctx.gotoAddress(c.address);
        }
        if (!c.analyzer.empty())
            ImGui::TextColored(theme::col::muted(), "Source: %s", c.analyzer.c_str());
        ImGui::Separator();
        ImGui::TextWrapped("%s", c.detail.c_str());
        ImGui::Separator();

        if (c.address && ctx.binary.loaded()) {
            size_t avail = 0;
            const uint8_t* p = ctx.binary.ptrFromVA(c.address, avail);
            if (!p) {
                ImGui::TextDisabled("(address not mapped to file data)");
            } else if (vaIsExecutable(ctx.binary, c.address) && ctx.disasm) {
                ImGui::TextDisabled("Disassembly at 0x%llX:", (unsigned long long)c.address);
                ui::PushMono();
                auto insns = ctx.disasm->disassemble(p, std::min<size_t>(avail, 80), c.address, 10);
                for (auto& in : insns)
                    ImGui::Text("0x%llX  %-8s %s", (unsigned long long)in.address, in.mnemonic.c_str(), in.operands.c_str());
                ui::PopMono();
            } else {
                ImGui::TextDisabled("Data at 0x%llX (use Find references in the Binary View for call sites):", (unsigned long long)c.address);
                ui::PushMono();
                size_t n = std::min<size_t>(avail, 64);
                for (size_t r = 0; r < n; r += 16) {
                    char line[96]; int o = 0;
                    o += std::snprintf(line + o, sizeof(line) - o, "%012llX  ", (unsigned long long)(c.address + r));
                    for (size_t col = 0; col < 16 && r + col < n; ++col)
                        o += std::snprintf(line + o, sizeof(line) - o, "%02X ", p[r + col]);
                    ImGui::TextUnformatted(line);
                }
                ui::PopMono();
            }
        }
    } else {
        ImGui::TextDisabled("Select a capability to view the associated code.");
    }
    ImGui::EndChild();
}

} // namespace ds
