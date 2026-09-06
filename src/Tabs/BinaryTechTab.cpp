#include "BinaryTechTab.h"
#include "../Core/BinaryFile.h"
#include "../Core/AlgoScan.h"
#include "../Core/PatchSet.h"
#include "../Ui/Fonts.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "../Ui/Splitter.h"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <exception>

namespace ds {

static DocumentResultIdentity currentTechIdentity(const AppContext& ctx) {
    const BinaryFile& binary = ctx.staticBinary();
    return MakeDocumentResultIdentity(
        ctx.staticDocumentId(), ctx.staticImageGeneration(), binary.loaded(),
        binary.loaded() ? binary.contentHash() : 0,
        binary.loaded() ? binary.imageRevision() : 0);
}

void BinaryTechTab::runTechScan(AppContext& ctx) {
    caps_.clear();
    owner_ = {};
    selected_ = -1;
    scanned_ = false;
    if (!ctx.staticBinary().loaded()) return;
    if (ctx.staticBinary().isMappedImage()) {
        status_ = "Open a file-backed binary or a reconstructed process dump to run Binary Tech.";
        return;
    }
    pending_ = true;
    status_.clear();

    const BinaryFile& active = ctx.staticBinary();
    const DocumentResultIdentity expected = currentTechIdentity(ctx);
    pendingOwner_ = expected;
    const std::string path = active.path();
    const bool raw = active.format() == BinFormat::Raw && !active.isMappedImage();
    const uint64_t rawBase = active.imageBase();
    const bool rawEntryExplicit = active.rawEntryExplicit();
    const uint64_t rawEntry = active.entryPointVA();
    const std::vector<AnalysisLandmark> landmarks = active.analysisLandmarks();
    std::vector<PjPatch> patches;
    const PjPatchSetPlan patchPlan = SnapshotActivePatchRecords(
        ctx.staticProject().patches, ctx.staticProject().patchSets, patches);
    const uint64_t request = requestSerial_.fetch_add(1, std::memory_order_acq_rel) + 1;

    if (worker_.joinable()) {
        worker_.request_stop();
        worker_.join();
    }
    if (!patchPlan.success) {
        pending_ = false;
        pendingOwner_ = {};
        status_ = std::string("Tech scan refused: invalid active patch selection (") +
                  PjPatchSetPlanErrorText(patchPlan.error) + ").";
        return;
    }
    try {
    worker_ = std::jthread(
        [this, request, expected, path, raw, rawBase, rawEntryExplicit, rawEntry,
         landmarks, patches](std::stop_token stop) mutable {
            WorkerResult result;
            result.request = request;
            result.owner = expected;
            try {
                BinaryFile binary;
                BinaryLoadOptions loadOptions;
                loadOptions.cancelled = [&stop] { return stop.stop_requested(); };
                const bool loaded = raw ? binary.loadRaw(path, rawBase, loadOptions)
                                        : binary.load(path, loadOptions);
                if (!loaded) {
                    result.error = "could not reload the source image for scanning";
                } else if (binary.contentHash() != expected.contentHash) {
                    result.error = "source file changed while the scan was queued";
                } else {
                    if (raw) {
                        if (rawEntryExplicit && !binary.setRawEntryPointVA(rawEntry))
                            result.error = "could not restore the Raw entry point";
                        if (result.error.empty() && !binary.setAnalysisLandmarks(std::move(landmarks)))
                            result.error = "could not restore the Raw analysis landmarks";
                    }
                    for (const PjPatch& patch : patches) {
                        if (!result.error.empty() || stop.stop_requested()) break;
                        if (!patch.bytes.empty() &&
                            binary.writeImage(patch.address, patch.bytes.data(), patch.bytes.size()) !=
                                patch.bytes.size())
                            result.error = "a saved patch no longer maps to the source image";
                    }
                    const auto cancelled = [&] { return stop.stop_requested(); };
                    if (result.error.empty() && !cancelled()) {
                        result.capabilities = ScanCapabilities(binary, cancelled);
                        if (!cancelled()) {
                            for (auto& algorithm : ScanAlgorithms(binary, nullptr, nullptr, cancelled)) {
                                Capability capability;
                                capability.name = algorithm.name;
                                capability.category = algorithm.category;
                                capability.confidence = algorithm.confidence;
                                capability.address = algorithm.address;
                                capability.addressValid = algorithm.addressValid;
                                capability.addresses = algorithm.dataVAs;
                                capability.hitCount = algorithm.dataVAs.size();
                                capability.detail = algorithm.detail +
                                    (algorithm.section.empty() ? std::string()
                                                               : "  [" + algorithm.section + "]");
                                capability.analyzer = "AlgoScan";
                                result.capabilities.push_back(std::move(capability));
                            }
                            std::sort(result.capabilities.begin(), result.capabilities.end(),
                                      [](const Capability& left, const Capability& right) {
                                          return left.confidence > right.confidence;
                                      });
                        }
                    }
                }
            } catch (const std::exception& exception) {
                result.error = std::string("tech scan failed: ") + exception.what();
            } catch (...) {
                result.error = "tech scan failed: unknown exception";
            }

            if (stop.stop_requested() ||
                requestSerial_.load(std::memory_order_acquire) != request)
                return;
            std::lock_guard lock(readyMutex_);
            ready_ = std::move(result);
        });
    } catch (const std::exception& exception) {
        cancelTechScan("Could not start the capability scan.");
        status_ += std::string(" ") + exception.what();
    }
}

void BinaryTechTab::pollTechScan(const DocumentResultIdentity& currentIdentity) {
    std::optional<WorkerResult> ready;
    {
        std::lock_guard lock(readyMutex_);
        if (ready_) ready.swap(ready_);
    }
    if (!ready) return;
    if (ready->request != requestSerial_.load(std::memory_order_acquire))
        return;
    pending_ = false;
    pendingOwner_ = {};
    if (!SameDocumentResultImage(ready->owner, currentIdentity)) {
        status_ = "The source document changed. Run a new scan for this binary.";
        return;
    }
    if (!ready->error.empty()) {
        status_ = std::move(ready->error);
        scanned_ = false;
        return;
    }
    caps_ = std::move(ready->capabilities);
    selected_ = caps_.empty() ? -1 : 0;
    owner_ = ready->owner;
    scanned_ = true;
    status_.clear();
}

void BinaryTechTab::cancelTechScan(const char* status) {
    requestSerial_.fetch_add(1, std::memory_order_acq_rel);
    worker_.request_stop();
    pending_ = false;
    pendingOwner_ = {};
    status_ = status;
}

// Is the section containing `va` executable? (controls disasm vs hex preview)
static bool vaIsExecutable(const BinaryFile& bin, uint64_t va) {
    if (va < bin.imageBase()) return false;
    const uint64_t rva = va - bin.imageBase();
    for (const auto& s : bin.sections())
        if (rva >= s.virtualAddress && rva - s.virtualAddress < s.virtualSize) return s.executable;
    return false;
}

void BinaryTechTab::render(AppContext& ctx) {
    const DocumentResultIdentity currentIdentity = currentTechIdentity(ctx);
    // In-flight work has its own owner: the published-result owner is empty
    // until completion, so it cannot invalidate a scan during a document switch.
    if (pending_ && !SameDocumentResultImage(pendingOwner_, currentIdentity))
        cancelTechScan("The source document changed. Run a new scan for this binary.");
    pollTechScan(currentIdentity);
    if (owner_ && !SameDocumentResultImage(owner_, currentIdentity)) {
        caps_.clear();
        owner_ = {};
        selected_ = -1;
        scanned_ = false;
    }

    // No binary: a hero card with the open action instead of a disabled form.
    if (!ctx.staticBinary().loaded()) {
        if (ui::EmptyState(DS_ICON_SHIELD, "No binary loaded",
                           "Open a binary to detect capabilities from imports, section names, and byte patterns.",
                           "Open Binary..."))
            ctx.openBinaryDialog();
        return;
    }
    if (ctx.staticBinary().isMappedImage()) {
        if (ui::EmptyState(DS_ICON_SHIELD, "Open a file-backed image",
                           "Binary Tech scans file-backed binaries. Open this module's on-disk binary, "
                           "or open a reconstructed process dump to inspect its capabilities.",
                           "Open Binary..."))
            ctx.openBinaryDialog();
        return;
    }

    ImGui::BeginDisabled(pending_);
    if (ui::ToolbarIconButton(DS_ICON_SHIELD, "Run Tech Scan",
                              "Detect capabilities and techniques from imports, section names, and byte patterns"))
        runTechScan(ctx);
    ImGui::EndDisabled();
    if (pending_) {
        ctx.wantContinuousRedraw = true;
        ui::SameLineIfFits(90.0f * theme::UiScale());
        if (ui::ToolbarIconButton(DS_ICON_STOP, "Cancel", "Cancel the capability scan"))
            cancelTechScan("Scan cancelled.");
    }
    ui::SameLineIfFits(240.0f * theme::UiScale());
    ui::SearchBox("##techfilter", "filter capabilities or evidence...", filter_, sizeof(filter_),
                  std::min(240.0f * theme::UiScale(), ImGui::GetContentRegionAvail().x));
    ui::SameLineIfFits(140.0f * theme::UiScale());
    if (pending_) ImGui::TextDisabled("scanning...");
    else if (scanned_) ImGui::TextDisabled("%d capabilit%s", (int)caps_.size(), caps_.size() == 1 ? "y" : "ies");
    else          ImGui::TextDisabled("not scanned");
    if (!status_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::col::warn());
        ImGui::TextWrapped("%s", status_.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::Separator();

    if (pending_) {
        ImGui::TextDisabled("Scanning imports, sections, runtime wrappers, and byte signatures...");
        return;
    }
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

    std::vector<int> visible;
    const auto matches = [&](const std::string& text) {
        return std::search(text.begin(), text.end(), filter_, filter_ + std::char_traits<char>::length(filter_),
            [](unsigned char a, unsigned char b) { return std::tolower(a) == std::tolower(b); }) != text.end();
    };
    for (int i = 0; i < static_cast<int>(caps_.size()); ++i) {
        const auto& cap = caps_[i];
        if (!filter_[0] || matches(cap.name) || matches(cap.category) ||
            matches(cap.detail) || matches(cap.analyzer)) visible.push_back(i);
    }
    if (filter_[0] && visible.empty()) {
        if (ui::EmptyState(DS_ICON_SEARCH, "No matching capabilities",
                           "Try a capability name, category, or a word from the evidence.", "Clear filter"))
            filter_[0] = 0;
        return;
    }
    if (std::find(visible.begin(), visible.end(), selected_) == visible.end())
        selected_ = visible.empty() ? -1 : visible.front();

    // Resizable master/detail workspace: the findings list remains compact while
    // the evidence/disassembly preview receives the rest of the viewport.
    const float scale = theme::UiScale();
    if (listWidth_ <= 0.0f) listWidth_ = 340.0f * scale;
    const float workspaceWidth = std::max(1.0f, ImGui::GetContentRegionAvail().x);
    const float maxListWidth = std::max(1.0f, workspaceWidth -
        std::min(320.0f * scale, workspaceWidth * 0.5f) - 5.0f * scale);
    listWidth_ = std::clamp(listWidth_, std::min({230.0f * scale, workspaceWidth * 0.4f, maxListWidth}),
                           maxListWidth);
    ImGui::BeginChild("caplist", ImVec2(listWidth_, 0), ImGuiChildFlags_Borders);
    if (ImGui::BeginTable("caps", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Capability");
        ImGui::TableSetupColumn("Cat", ImGuiTableColumnFlags_WidthFixed, 84 * scale);
        ImGui::TableSetupColumn("Conf", ImGuiTableColumnFlags_WidthFixed, 46 * scale);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin(static_cast<int>(visible.size()));
        while (clip.Step()) for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
            const int i = visible[row];
            auto& c = caps_[i];
            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(c.name.c_str(), selected_ == i, ImGuiSelectableFlags_SpanAllColumns))
                selected_ = i;
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && c.addressValid)
                ctx.gotoAddress(c.address);
            ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", c.category.c_str());
            ImGui::TableSetColumnIndex(2);
            ImVec4 col = c.confidence > 0.85f ? theme::col::good()
                       : c.confidence > 0.65f ? theme::col::warn()
                                              : theme::col::bad();
            ImGui::TextColored(col, "%.0f%%", c.confidence * 100.0f);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ui::VSplitter("##tech_split", &listWidth_, std::min(230.0f * scale, workspaceWidth * 0.4f),
                  std::min(320.0f * scale, workspaceWidth * 0.5f), 5.0f * scale);
    ImGui::BeginChild("capdetail", ImVec2(0, 0), ImGuiChildFlags_Borders);
    if (selected_ >= 0 && selected_ < (int)caps_.size()) {
        auto& c = caps_[selected_];
        ImGui::TextColored(theme::col::accent(), "%s", c.name.c_str());
        if (c.addressValid)
            ImGui::TextDisabled("Category: %s   Confidence: %.0f%%   Address: 0x%llX",
                                c.category.c_str(), c.confidence * 100.0f,
                                (unsigned long long)c.address);
        else
            ImGui::TextDisabled("Category: %s   Confidence: %.0f%%   Address: unavailable",
                                c.category.c_str(), c.confidence * 100.0f);
        if (c.addressValid) {
            if (ImGui::SmallButton("View in disassembly")) ctx.gotoAddress(c.address);
        }
        if (c.category == "network") {
            ui::SameLineIfFits(ImGui::CalcTextSize("Open network trail").x + ImGui::GetStyle().FramePadding.x * 2);
            if (ImGui::SmallButton("Open network trail"))
                ctx.openCrackmeTriage(TriageWorkspaceView::NetworkTrail);
        }
        if (!c.analyzer.empty())
            ImGui::TextColored(theme::col::muted(), "Source: %s", c.analyzer.c_str());
        ImGui::Separator();
        ImGui::TextWrapped("%s", c.detail.c_str());
        ImGui::Separator();

        if (c.addressValid && ctx.staticBinary().loaded()) {
            size_t avail = 0;
            const uint8_t* p = ctx.staticBinary().ptrFromVA(c.address, avail);
            if (!p) {
                ImGui::TextDisabled("(address not mapped to file data)");
            } else if (vaIsExecutable(ctx.staticBinary(), c.address) &&
                       ctx.staticDisassembler()) {
                ImGui::TextDisabled("Disassembly at 0x%llX:", (unsigned long long)c.address);
                ui::PushMono();
                auto insns = ctx.staticDisassembler()->disassemble(
                    p, std::min<size_t>(avail, 80), c.address, 10);
                for (auto& in : insns) {
                    const std::string text = InstructionText(in);
                    ImGui::Text("0x%llX  %s", (unsigned long long)in.address, text.c_str());
                }
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
