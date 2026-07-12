#include "SigScannerTab.h"
#include "../Core/FunctionAnalyzer.h"
#include "../Core/ProcessManager.h"
#include "../Core/SigMatch.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"
#include <algorithm>
#include <cctype>
#include <cstdio>

namespace ds {

// Parse "48 89 ?? 24" into a SigPattern (bytes + wildcard mask) via the shared
// masked matcher's parser, which keeps identical semantics (single/double '?'
// wildcards, hex pairs, spaces ignored). Returns false if malformed.
static bool parsePattern(const std::string& in, SigPattern& pat) {
    return ParseSignature(in, pat);
}

// Count occurrences of a pattern in the loaded image. -1 = malformed pattern.
static int countMatches(const BinaryFile& bin, const std::string& pattern, size_t cap = 100000) {
    SigPattern pat;
    if (!parsePattern(pattern, pat)) return -1;
    const auto& d = bin.bytes();
    if (d.size() < pat.size()) return 0;
    return (int)FindAllMasked(d.data(), d.size(), pat, cap).size();
}

static std::string healthFromCount(int count) {
    return count < 0 ? "malformed" : count == 0 ? "none" : count == 1 ? "unique" : "multiple";
}

void SigScannerTab::refreshHealth(AppContext& ctx) {
    for (auto& s : sigs_) {
        if (!ctx.binary.loaded()) { s.count = -1; s.health = "n/a"; continue; }
        s.count  = countMatches(ctx.binary, s.pattern);
        s.health = healthFromCount(s.count);
    }
}

void SigScannerTab::scan(AppContext& ctx) {
    results_.clear();
    progress_ = 0.0f;
    truncated_ = false;

    SigPattern pat;
    if (!parsePattern(patternInput_, pat)) return;

    // Live mode: walk the attached process's committed memory (works paused or
    // running) instead of the on-disk file. Hits report their runtime VA and the
    // module they fall in. Reads are chunked with a (pat-1)-byte overlap so a
    // match straddling two chunks is never dropped.
    if (live_) {
        DbgSnapshot snap = ctx.debug.snapshot();
        if (!snap.attached()) return;
        ProcessManager pm;
        std::vector<ModuleInfo> mods = pm.modules(snap.pid);
        auto moduleAt = [&](uint64_t va) -> std::string {
            for (const auto& m : mods)
                if (va >= m.base && va < m.base + m.size)
                    return m.name.empty() ? m.path : m.name;
            return std::string("live");
        };
        // Region protection suffix (r/w/x) appended to the module column, so a hit
        // in writable scratch memory is distinguishable from one in mapped code.
        auto protOf = [](const MemRegion& rg) -> std::string {
            std::string p = " [";
            p += rg.read  ? 'r' : '-';
            p += rg.write ? 'w' : '-';
            p += rg.exec  ? 'x' : '-';
            p += ']';
            return p;
        };
        const size_t kChunk      = 1u << 20;          // 1 MB read window
        const size_t kByteBudget = 512ull << 20;      // stay responsive on big targets
        const size_t overlap     = pat.size() - 1;
        size_t scanned = 0;
        std::vector<uint8_t> buf;
        auto regions = ctx.debug.regions();
        for (size_t ri = 0; ri < regions.size() && scanned < kByteBudget && results_.size() <= 4096; ++ri) {
            const auto& rg = regions[ri];
            progress_ = (float)ri / (float)std::max<size_t>(1, regions.size());
            if (!rg.read || rg.state != 0x1000 /*MEM_COMMIT*/ || rg.size < pat.size()) continue;
            for (uint64_t off = 0; off < rg.size && scanned < kByteBudget && results_.size() <= 4096;) {
                size_t want = (size_t)std::min<uint64_t>(kChunk, rg.size - off);
                buf.resize(want);
                // Masked read: our own 0xCC software-breakpoint bytes are substituted
                // back to the originals, so a pattern crossing a breakpoint still hits.
                size_t got = ctx.debug.readMemoryMasked(rg.base + off, buf.data(), want);
                scanned += got;
                if (got >= pat.size()) {
                    // Collect up to the remaining result budget in this chunk; the
                    // masked Boyer-Moore-Horspool matcher reports every (overlapping)
                    // hit offset within [buf, buf+got) in ascending order.
                    size_t room = (results_.size() <= 4096) ? (4096 - results_.size() + 1) : 0;
                    if (room) {
                        for (size_t i : FindAllMasked(buf.data(), got, pat, room)) {
                            uint64_t va = rg.base + off + i;
                            results_.push_back({ va, patternInput_, moduleAt(va) + protOf(rg) });
                            if (results_.size() > 4096) { truncated_ = true; break; }
                        }
                    }
                }
                if (got < want) break;                // short read: rest of region unreadable
                off += (want > overlap) ? (want - overlap) : want;
            }
        }
        if (truncated_) results_.pop_back();   // drop the one-over sentinel: display exactly the 4096 cap
        progress_ = 1.0f;
        char tm[80];
        std::snprintf(tm, sizeof(tm), "Live scan: %d match(es)%s.", (int)results_.size(),
                      truncated_ ? " (capped)" : "");
        ui::Toast(truncated_ ? ui::ToastKind::Warn : ui::ToastKind::Info, tm);
        return;
    }

    if (!ctx.binary.loaded()) return;
    const auto& d = ctx.binary.bytes();
    if (d.size() < pat.size()) return;

    // Collect every (overlapping) match via the shared masked matcher, bounded by
    // one over the display cap so we can tell when results were truncated.
    const size_t kCap = 4097;
    std::vector<size_t> offs = FindAllMasked(d.data(), d.size(), pat, kCap);
    for (size_t i : offs) {
        // Map file offset back to its mapped VA (shared with strings/byte search).
        uint64_t va;
        if (ctx.binary.offsetToVA(i, va)) {
            results_.push_back({ va, patternInput_, ctx.binary.path() });
            if (results_.size() > 4096) { truncated_ = true; break; }
        }
    }
    if (truncated_) results_.pop_back();   // drop the one-over sentinel: display exactly the 4096 cap
    progress_ = 1.0f;
    char tm[80];
    std::snprintf(tm, sizeof(tm), "Scan: %d match(es)%s.", (int)results_.size(),
                  truncated_ ? " (capped)" : "");
    ui::Toast(truncated_ ? ui::ToastKind::Warn : ui::ToastKind::Info, tm);
}

void SigScannerTab::render(AppContext& ctx) {
    // A signature created from the Binary View's right-click menu arrives here:
    // load it into the pattern box, jump to Results, and scan immediately.
    if (!ctx.pendingSignature.empty()) {
        // Scan in the mode the signature was built in: a signature captured from the live
        // listing carries runtime bytes that won't match the on-disk image, so it must be
        // scanned against process memory, not the file.
        live_ = ctx.pendingSignatureLive;
        patternClipped_ = ctx.pendingSignature.size() >= sizeof(patternInput_);   // defensive: buffer holds the worst case
        std::snprintf(patternInput_, sizeof(patternInput_), "%s", ctx.pendingSignature.c_str());
        ctx.pendingSignature.clear();
        scan(ctx);   // populate Results (the default sub-tab) right away
    }
    DbgSnapshot snap = ctx.debug.snapshot();
    // Nothing to scan against at all: a hero card instead of a dead form.
    if (!ctx.binary.loaded() && !snap.attached()) {
        if (ui::EmptyState(DS_ICON_SEARCH, "Nothing to scan",
                           "Open a binary to scan for byte patterns, or attach a process for live scans.",
                           "Open Binary..."))
            ctx.openBinaryDialog();
        return;
    }

    // ---- Toolbar: pattern + scan + live | name + save | progress / warnings ----
    const float s = theme::UiScale();
    ImGui::SetNextItemWidth(std::max(280.0f * s, ImGui::GetContentRegionAvail().x * 0.40f));
    if (ImGui::InputTextWithHint("##pattern", "AA BB ?? DD pattern...", patternInput_, sizeof(patternInput_)))
        patternClipped_ = false;   // the box no longer holds the clipped handoff pattern
    ImGui::SameLine();
    bool canScan = live_ ? snap.attached() : ctx.binary.loaded();
    ImGui::BeginDisabled(!canScan);
    if (ui::ToolbarIconButton(DS_ICON_SEARCH, "Scan",
                              live_ ? "Scan the attached process's memory" : "Scan the loaded file"))
        scan(ctx);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Checkbox("Live", &live_)) { results_.clear(); progress_ = 0.0f; }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Scan the attached process's committed memory (works paused or running) instead of the file on disk.");
    ImGui::SameLine(); ImGui::TextDisabled("|"); ImGui::SameLine();
    ImGui::SetNextItemWidth(140.0f * s);
    ImGui::InputTextWithHint("##signame", "signature name", sigName_, sizeof(sigName_));
    ImGui::SameLine();
    if (ui::ToolbarIconButton(DS_ICON_SAVE, "Save Sig", "Store the pattern in the Sig Health list")) {
        Sig s2{ sigName_, patternInput_, "?", -1 };
        if (ctx.binary.loaded()) { s2.count = countMatches(ctx.binary, s2.pattern); s2.health = healthFromCount(s2.count); }
        sigs_.push_back(std::move(s2));
        ui::Toast(ui::ToastKind::Success,
                  sigName_[0] ? std::string("Signature '") + sigName_ + "' saved." : "Signature saved.");
    }
    ImGui::SameLine();
    ImGui::ProgressBar(progress_, ImVec2(140.0f * s, 0));
    if (patternClipped_) {
        ImGui::SameLine();
        ui::Badge("signature truncated", theme::col::warn());
    }

    if (ImGui::BeginTabBar("sigsub")) {
        if (ImGui::BeginTabItem("Results")) {
            ImGui::Text("%d match(es)", (int)results_.size());
            ImGui::SameLine();
            ImGui::TextDisabled(live_ ? "(live process memory)" : "(file on disk)");
            if (truncated_) {
                ImGui::SameLine();
                ImGui::TextColored(theme::col::warn(), "(capped at %d \xE2\x80\x94 refine the pattern)",
                                   (int)results_.size());
            }
            if (ImGui::BeginTable("res", 3,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160);
                ImGui::TableSetupColumn("Signature");
                ImGui::TableSetupColumn("Module");
                ImGui::TableHeadersRow();
                ImGuiListClipper clip;   // up to 4096 rows -> only build widgets for the visible ones
                clip.Begin((int)results_.size());
                while (clip.Step())
                    for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                        auto& r = results_[(size_t)i];
                        ImGui::TableNextRow();
                        ImGui::PushID((void*)(uintptr_t)r.address);
                        ImGui::TableSetColumnIndex(0);
                        char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)r.address);
                        // Live hits are runtime VAs -> open the live view; file hits are file VAs.
                        if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) {
                            if (live_) ctx.gotoAddressLive(r.address); else ctx.gotoAddress(r.address);
                        }
                        ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(r.sig.c_str());
                        ImGui::TableSetColumnIndex(2); ImGui::TextDisabled("%s", r.module.c_str());
                        ImGui::PopID();
                    }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Current Scan")) {
            ImGui::Text("Pattern: %s", patternInput_);
            ImGui::Text("Bytes loaded: %zu", ctx.binary.bytes().size());
            ImGui::ProgressBar(progress_, ImVec2(-1, 0));
            ImGui::TextDisabled("Live scan progress and the active pattern appear here.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Sig Health")) {
            ImGui::BeginDisabled(!ctx.binary.loaded());
            if (ImGui::Button("Recompute health")) refreshHealth(ctx);
            ImGui::EndDisabled();
            ImGui::SameLine();
            ImGui::TextDisabled(ctx.binary.loaded() ? "match count vs the loaded binary: none / unique / multiple"
                                                     : "load a binary to score signatures");
            if (ImGui::BeginTable("health", 4,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 140);
                ImGui::TableSetupColumn("Pattern");
                ImGui::TableSetupColumn("Matches", ImGuiTableColumnFlags_WidthFixed, 70);
                ImGui::TableSetupColumn("Health", ImGuiTableColumnFlags_WidthFixed, 90);
                ImGui::TableHeadersRow();
                for (auto& s : sigs_) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(s.name.c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", s.pattern.c_str());
                    ImGui::TableSetColumnIndex(2);
                    if (s.count < 0) ImGui::TextDisabled("-");
                    else             ImGui::Text("%d", s.count);
                    ImGui::TableSetColumnIndex(3);
                    ImVec4 col = s.health == "unique"   ? ImVec4(0.4f,0.9f,0.4f,1)
                               : s.health == "multiple" ? ImVec4(0.95f,0.7f,0.3f,1)
                               : s.health == "none"     ? ImVec4(0.9f,0.5f,0.5f,1)
                               : ImVec4(0.7f,0.7f,0.7f,1);
                    ImGui::TextColored(col, "%s", s.health.c_str());
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("All Functions")) {
            ImGui::BeginDisabled(!ctx.binary.loaded() || !ctx.disasm);
            if (ImGui::Button("Analyze Functions")) {
                FunctionAnalyzer fa;
                auto found = fa.analyze(ctx.binary, *ctx.disasm, ctx.arch);
                functions_.clear();
                functions_.reserve(found.size());
                for (auto& f : found)
                    functions_.push_back({ f.address, f.name, f.size });
                analyzeSummary_ = fa.lastSummary();
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            ImGui::SetNextItemWidth(200);
            ImGui::InputTextWithHint("##fnfilter", "filter name...", fnFilter_, sizeof(fnFilter_));
            ImGui::SameLine();
            if (!analyzeSummary_.empty()) ImGui::TextDisabled("%s", analyzeSummary_.c_str());
            else ImGui::TextDisabled("Recursive-descent + prologue + export sweep.");

            if (ImGui::BeginTable("fns", 3,
                    ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
                    ImVec2(0, ImGui::GetContentRegionAvail().y))) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160);
                ImGui::TableSetupColumn("Name");
                ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 70);
                ImGui::TableHeadersRow();
                // Pre-filter into a dense index list so a uniform-height clipper can
                // skip the off-screen rows (this list can hold thousands of entries).
                std::vector<int> vis;
                vis.reserve(functions_.size());
                for (int i = 0; i < (int)functions_.size(); ++i)
                    if (!fnFilter_[0] || functions_[(size_t)i].name.find(fnFilter_) != std::string::npos)
                        vis.push_back(i);
                ImGuiListClipper clip;
                clip.Begin((int)vis.size());
                while (clip.Step())
                    for (int vi = clip.DisplayStart; vi < clip.DisplayEnd; ++vi) {
                        auto& f = functions_[(size_t)vis[(size_t)vi]];
                        ImGui::TableNextRow();
                        ImGui::PushID((void*)(uintptr_t)f.address);
                        ImGui::TableSetColumnIndex(0);
                        char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)f.address);
                        if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) ctx.gotoAddress(f.address);
                        ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(f.name.c_str());
                        ImGui::TableSetColumnIndex(2); ImGui::Text("%u", f.size);
                        ImGui::PopID();
                    }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

} // namespace ds
