#include "BinaryDiffTab.h"
#include "../Ui/Fonts.h"
#include "../Ui/Theme.h"
#include "../Core/DiffRegions.h"
#include "../Disasm/DisassemblerFactory.h"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <windows.h>
#include <commdlg.h>

namespace ds {

static std::string baseName(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p : p.substr(s + 1);
}

// Map a loaded binary's machine type to the disassembler Arch enum (mirrors the
// shell's archFromMachine; kept local so the diff tab needs no AppContext).
static Arch archOf(const BinaryFile& bf) {
    switch (bf.machine()) {
        case MachineArch::X86:     return Arch::X86;
        case MachineArch::X64:     return Arch::X64;
        case MachineArch::ARM:     return Arch::ARM;
        case MachineArch::ARM64:   return Arch::ARM64;
        case MachineArch::MIPS:    return Arch::MIPS;
        case MachineArch::MIPS64:  return Arch::MIPS64;
        case MachineArch::PPC:     return Arch::PPC;
        case MachineArch::PPC64:   return Arch::PPC64;
        case MachineArch::RISCV:   return Arch::RISCV32;
        case MachineArch::RISCV64: return Arch::RISCV64;
        case MachineArch::JVM:     return Arch::JVM;
        default:                   return bf.is64Bit() ? Arch::X64 : Arch::X86;
    }
}

// Locate the section of `bf` whose raw file data covers file offset `off`.
// Returns nullptr if the offset is outside every section's raw range.
static const Section* sectionAtOffset(const BinaryFile& bf, uint64_t off) {
    for (const auto& s : bf.sections())
        if (s.rawSize && off >= s.rawOffset && off < s.rawOffset + s.rawSize) return &s;
    return nullptr;
}

void BinaryDiffTab::openInto(BinaryFile& target) {
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"Binaries\0*.exe;*.dll;*.sys;*.bin\0All Files\0*.*\0";
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) {
        char path[MAX_PATH * 2] = {0};
        WideCharToMultiByte(CP_UTF8, 0, file, -1, path, sizeof(path), nullptr, nullptr);
        target.load(path);
        computed_ = false;
    }
}

void BinaryDiffTab::computeDiff() {
    diffs_.clear();
    totalDiff_ = 0;
    if (!left_.loaded() || !right_.loaded()) return;
    const auto& a = left_.bytes();
    const auto& b = right_.bytes();
    size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) {
            ++totalDiff_;
            if (diffs_.size() < 5000) diffs_.push_back({ i, a[i], b[i] });
        }
    }
    totalDiff_ += (a.size() > b.size() ? a.size() - b.size() : b.size() - a.size());
    computed_ = true;
    buildRegions();
    if (sectionAware_) computeSectionDiff();
}

// Coalesce differing file offsets into navigable regions (pure logic in
// Core/DiffRegions.h, unit-tested separately). Independent of the diffs_ cap.
void BinaryDiffTab::buildRegions() {
    regions_.clear();
    curRegion_ = -1;
    if (!left_.loaded() || !right_.loaded()) return;
    const auto& a = left_.bytes();
    const auto& b = right_.bytes();
    std::vector<ByteDiffRegion> out;
    CoalesceDiffRegions(a.data(), a.size(), b.data(), b.size(), /*gap=*/16, /*maxRegions=*/50000, out);
    regions_.reserve(out.size());
    for (const auto& r : out) regions_.push_back({ r.start, r.end });
}

void BinaryDiffTab::gotoRegion(int idx) {
    if (idx < 0 || idx >= (int)regions_.size()) return;
    curRegion_ = idx;
    // Back up a few rows so the change sits below the top edge with some context.
    float row = (float)(regions_[idx].start / 16) - 3.0f;
    if (row < 0) row = 0;
    scrollY_ = row * ImGui::GetTextLineHeightWithSpacing();
    applyScroll_ = true;   // force both panes to this position next render
}

// (Re)build a decoder for each side whenever that file's architecture changes.
void BinaryDiffTab::ensureDecoders() {
    if (left_.loaded() && (!leftDis_ || leftDisArch_ != left_.machine())) {
        leftDisArch_ = left_.machine();
        leftDis_ = MakeDisassembler(Engine::Zydis, archOf(left_));
    }
    if (right_.loaded() && (!rightDis_ || rightDisArch_ != right_.machine())) {
        rightDisArch_ = right_.machine();
        rightDis_ = MakeDisassembler(Engine::Zydis, archOf(right_));
    }
}

// Section-aware diff: pair each LEFT section with a RIGHT section sharing its
// name (or, failing that, its RVA), then byte-diff the two sections' raw data
// aligned at their respective section starts. This keeps a shifted/relocated
// section from registering as wholly different the way a flat offset diff would.
void BinaryDiffTab::computeSectionDiff() {
    secDiffs_.clear();
    secTotalDiff_ = 0;
    secUnmatched_ = 0;
    if (!left_.loaded() || !right_.loaded()) return;

    const auto& la = left_.bytes();
    const auto& rb = right_.bytes();
    const auto& rsecs = right_.sections();

    // Find a right-side section matching by name first, then by RVA.
    auto findRight = [&](const Section& ls) -> const Section* {
        for (const auto& rs : rsecs) if (!rs.name.empty() && rs.name == ls.name) return &rs;
        for (const auto& rs : rsecs) if (rs.virtualAddress == ls.virtualAddress) return &rs;
        return nullptr;
    };

    for (const auto& ls : left_.sections()) {
        SecDiff sd;
        sd.name = ls.name;
        sd.rva  = ls.virtualAddress;
        sd.lOff = ls.rawOffset;
        const Section* rs = findRight(ls);
        if (!rs) { ++secUnmatched_; secDiffs_.push_back(std::move(sd)); continue; }
        sd.matched = true;
        sd.rOff = rs->rawOffset;

        // Compare the on-disk overlap of the two sections, bounded by what is
        // actually present in each file's byte buffer (raw sizes can lie).
        uint64_t lAvail = (ls.rawOffset < la.size()) ? (la.size() - ls.rawOffset) : 0;
        uint64_t rAvail = (rs->rawOffset < rb.size()) ? (rb.size() - rs->rawOffset) : 0;
        size_t len = (size_t)std::min({ (uint64_t)ls.rawSize, (uint64_t)rs->rawSize, lAvail, rAvail });
        sd.len = len;
        for (size_t i = 0; i < len; ++i)
            if (la[ls.rawOffset + i] != rb[rs->rawOffset + i]) ++sd.diffBytes;
        // Size mismatch within the section counts as additional differing bytes.
        uint64_t lraw = std::min<uint64_t>(ls.rawSize, lAvail);
        uint64_t rraw = std::min<uint64_t>(rs->rawSize, rAvail);
        sd.diffBytes += (size_t)(lraw > rraw ? lraw - rraw : rraw - lraw);
        secTotalDiff_ += sd.diffBytes;
        secDiffs_.push_back(std::move(sd));
    }
    // Right-only sections (present on the right but with no left match) are also
    // unmatched evidence.
    for (const auto& rs : rsecs) {
        bool inLeft = false;
        for (const auto& ls : left_.sections())
            if ((!rs.name.empty() && rs.name == ls.name) || rs.virtualAddress == ls.virtualAddress) { inLeft = true; break; }
        if (!inLeft) ++secUnmatched_;
    }
}

void BinaryDiffTab::render(AppContext& ctx) {
    (void)ctx;

    // Before a diff exists, show a centered "drop zone": two load containers
    // forming one half-width block, centered horizontally and vertically.
    if (!computed_) {
        renderLoadZone();
        return;
    }

    // Compact toolbar: swap files or recompute without leaving the diff view.
    if (ImGui::Button("Load Left...")) openInto(left_);
    ImGui::SameLine();
    ImGui::TextDisabled("%s", left_.loaded() ? baseName(left_.path()).c_str() : "(none)");
    ImGui::SameLine(0, 16);
    if (ImGui::Button("Load Right...")) openInto(right_);
    ImGui::SameLine();
    ImGui::TextDisabled("%s", right_.loaded() ? baseName(right_.path()).c_str() : "(none)");
    ImGui::SameLine(0, 16);
    ImGui::BeginDisabled(!(left_.loaded() && right_.loaded()));
    if (ImGui::Button("Recompute")) computeDiff();
    ImGui::EndDisabled();
    ImGui::SameLine();
    // Section-aware alignment toggle: recompute immediately so the summary +
    // (when on) the per-section breakdown reflect the chosen mode.
    if (ImGui::Checkbox("Section-aware", &sectionAware_)) computeDiff();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Align matching sections (by name, else RVA) before diffing,\n"
                          "instead of comparing by flat file offset.");
    ImGui::SameLine();
    ImGui::Text("| Left: %zu B   Right: %zu B", left_.bytes().size(), right_.bytes().size());
    ImGui::Separator();

    // Section-aware breakdown: a compact per-section diff table above the synced
    // hex panes (the hex panes still show the flat byte view for navigation).
    if (sectionAware_) {
        size_t matchedCount = 0;
        for (const auto& sd : secDiffs_) if (sd.matched) ++matchedCount;
        ImGui::Text("Section-aware: %zu differing byte(s) across %zu matched section(s)",
                    secTotalDiff_, matchedCount);
        if (secUnmatched_) {
            ImGui::SameLine();
            ImGui::TextColored(theme::col::warn(), "  %zu section(s) present on only one side", secUnmatched_);
        }
        float tableH = std::min(ImGui::GetContentRegionAvail().y * 0.35f, 160.0f * theme::UiScale());
        if (ImGui::BeginTable("secdiff", 5,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
                ImVec2(0, tableH))) {
            ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 120.0f * theme::UiScale());
            ImGui::TableSetupColumn("RVA",     ImGuiTableColumnFlags_WidthFixed, 110.0f * theme::UiScale());
            ImGui::TableSetupColumn("Compared",ImGuiTableColumnFlags_WidthFixed, 90.0f * theme::UiScale());
            ImGui::TableSetupColumn("Diff",    ImGuiTableColumnFlags_WidthFixed, 90.0f * theme::UiScale());
            ImGui::TableSetupColumn("Status");
            ImGui::TableHeadersRow();
            for (const auto& sd : secDiffs_) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(sd.name.c_str());
                ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)sd.rva);
                ImGui::TableSetColumnIndex(2); ImGui::Text("%zu B", sd.len);
                ImGui::TableSetColumnIndex(3);
                if (!sd.matched)         ImGui::TextDisabled("-");
                else if (sd.diffBytes)   ImGui::TextColored(theme::col::bad(),  "%zu", sd.diffBytes);
                else                     ImGui::TextColored(theme::col::good(), "0");
                ImGui::TableSetColumnIndex(4);
                if (!sd.matched)         ImGui::TextColored(theme::col::warn(), "no match (left only)");
                else if (sd.diffBytes)   ImGui::TextUnformatted("changed");
                else                     ImGui::TextDisabled("identical");
            }
            ImGui::EndTable();
        }
        ImGui::Separator();
    }

    const size_t maxN = std::max(left_.bytes().size(), right_.bytes().size());
    const int    rows = (int)((maxN + 15) / 16);

    ImGui::Text("Differing bytes (overlap): %zu", totalDiff_);
    ImGui::SameLine();
    ImGui::TextDisabled("   red = byte differs, yellow = selected change");

    // Difference navigation: jump between coalesced change regions; F3 / Shift+F3
    // step forward / back while the tab is focused. Selecting a region scrolls both
    // panes to it and drives the side-by-side ASM panel below.
    const int nReg = (int)regions_.size();
    bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows);
    ImGui::BeginDisabled(nReg == 0);
    bool prev = ImGui::Button("\xE2\x97\x80 Prev") ||
                (focused && ImGui::IsKeyPressed(ImGuiKey_F3) && ImGui::GetIO().KeyShift);
    ImGui::SameLine();
    bool next = ImGui::Button("Next \xE2\x96\xB6") ||
                (focused && ImGui::IsKeyPressed(ImGuiKey_F3) && !ImGui::GetIO().KeyShift);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (nReg) ImGui::Text("Change %d / %d  @ 0x%llX", curRegion_ + 1, nReg,
                          (unsigned long long)(curRegion_ >= 0 ? regions_[curRegion_].start : regions_[0].start));
    else      ImGui::TextDisabled("(no differences)");
    if (next && nReg) gotoRegion(curRegion_ + 1 >= nReg ? 0 : curRegion_ + 1);
    if (prev && nReg) gotoRegion(curRegion_ <= 0 ? nReg - 1 : curRegion_ - 1);

    // Reserve room at the bottom for the ASM panel once a region is selected.
    const float asmH = (curRegion_ >= 0) ? 200.0f * theme::UiScale() : 0.0f;

    // Two equal, bordered containers side by side (symmetric = visually centered).
    ImVec2 avail = ImGui::GetContentRegionAvail();
    const float gap   = 12.0f;
    const float paneW = (avail.x - gap) * 0.5f;
    const float paneH = avail.y - (asmH > 0 ? asmH + ImGui::GetStyle().ItemSpacing.y : 0);

    const bool force = applyScroll_;
    float ls = scrollY_, rs = scrollY_;
    bool  lhov = false, rhov = false;

    // LEFT container.
    ImGui::BeginChild("Lcont", ImVec2(paneW, paneH), ImGuiChildFlags_Borders);
    ImGui::TextColored(theme::col::accent(), "%s", baseName(left_.path()).c_str());
    ImGui::SameLine(); ImGui::TextDisabled("(%zu B)", left_.bytes().size());
    ImGui::Separator();
    renderPane("Lhex", left_, right_, rows, leftMaster_, ls, lhov, force);
    ImGui::EndChild();

    ImGui::SameLine(0, gap);

    // RIGHT container.
    ImGui::BeginChild("Rcont", ImVec2(paneW, paneH), ImGuiChildFlags_Borders);
    ImGui::TextColored(theme::col::accent(), "%s", baseName(right_.path()).c_str());
    ImGui::SameLine(); ImGui::TextDisabled("(%zu B)", right_.bytes().size());
    ImGui::Separator();
    renderPane("Rhex", right_, left_, rows, !leftMaster_, rs, rhov, force);
    ImGui::EndChild();

    if (force) {
        applyScroll_ = false;   // scrollY_ stays at the forced target
    } else {
        // The hovered pane drives the shared scroll; the other follows next frame.
        scrollY_ = leftMaster_ ? ls : rs;
        if (lhov)      leftMaster_ = true;
        else if (rhov) leftMaster_ = false;
    }

    // Side-by-side disassembly of the selected change.
    if (curRegion_ >= 0) renderDiffAsm();
}

// Disassemble the bytes around the selected region in both binaries and show them
// side by side, highlighting the instructions that overlap the changed bytes. A
// region that falls in a non-executable section is shown as raw bytes instead.
void BinaryDiffTab::renderDiffAsm() {
    if (curRegion_ < 0 || curRegion_ >= (int)regions_.size()) return;
    ensureDecoders();
    const DiffRegion reg = regions_[curRegion_];

    ImGui::BeginChild("DiffAsm", ImVec2(0, 0), ImGuiChildFlags_Borders);
    ImGui::TextColored(theme::col::accent(), "Disassembly at change 0x%llX \xE2\x80\x93 0x%llX",
                       (unsigned long long)reg.start, (unsigned long long)reg.end);
    ImGui::Separator();

    const float gap   = 12.0f;
    const float colW  = (ImGui::GetContentRegionAvail().x - gap) * 0.5f;

    auto renderSide = [&](const char* id, const char* label, const BinaryFile& bf, IDisassembler* dis) {
        ImGui::BeginChild(id, ImVec2(colW, 0), ImGuiChildFlags_Borders);
        ImGui::TextColored(theme::col::accent(), "%s", label);
        ImGui::SameLine(); ImGui::TextDisabled("(%s)", ArchName(archOf(bf)));
        ImGui::Separator();
        ui::PushMono();
        const auto& bytes = bf.bytes();
        const Section* sec = sectionAtOffset(bf, reg.start);
        if (reg.start >= bytes.size()) {
            ImGui::TextDisabled("(offset past end of this file)");
        } else if (!sec || !sec->executable || !dis) {
            // Data (or unknown) region: show the raw changed bytes instead of code.
            ImGui::TextDisabled("data");
            std::string hx;
            for (uint64_t o = reg.start; o < reg.end && o < bytes.size(); ++o) {
                char t[4]; std::snprintf(t, sizeof(t), "%02X ", bytes[(size_t)o]); hx += t;
            }
            ImGui::TextWrapped("%s", hx.c_str());
        } else {
            // Start ~32 bytes before the change (clamped to the section start) so
            // the decode self-syncs onto an instruction boundary before the region.
            uint64_t secStart = sec->rawOffset;
            uint64_t winOff = (reg.start > secStart + 32) ? reg.start - 32 : secStart;
            uint64_t secEnd = std::min<uint64_t>(sec->rawOffset + sec->rawSize, bytes.size());
            uint64_t off = winOff;
            int guard = 0;
            while (off < secEnd && off < reg.end + 16 && guard++ < 256) {
                uint64_t va = 0; bf.offsetToVA(off, va);
                Instruction in;
                size_t avail = (size_t)(secEnd - off);
                bool ok = dis->decodeOne(bytes.data() + off, avail, va, in) && in.length;
                uint32_t len = ok ? in.length : 1;
                bool changed = (off < reg.end) && (off + len > reg.start);   // overlaps the change
                if (changed) {
                    ImVec2 p0 = ImGui::GetCursorScreenPos();
                    ImGui::GetWindowDrawList()->AddRectFilled(
                        p0, ImVec2(p0.x + ImGui::GetContentRegionAvail().x, p0.y + ImGui::GetTextLineHeight()),
                        ImGui::GetColorU32(ImVec4(0.55f, 0.45f, 0.10f, 0.45f)));
                }
                ImVec4 col = changed ? ImVec4(1.0f, 0.92f, 0.55f, 1.0f) : theme::col::muted();
                if (ok) ImGui::TextColored(col, "%08llX  %-8s %s",
                                           (unsigned long long)va, in.mnemonic.c_str(), in.operands.c_str());
                else    ImGui::TextColored(col, "%08llX  db 0x%02X",
                                           (unsigned long long)va, bytes[(size_t)off]);
                off += len;
            }
        }
        ui::PopMono();
        ImGui::EndChild();
    };

    renderSide("AsmL", "OLD (left)",  left_,  leftDis_.get());
    ImGui::SameLine(0, gap);
    renderSide("AsmR", "NEW (right)", right_, rightDis_.get());

    ImGui::EndChild();
}

void BinaryDiffTab::renderLoadZone() {
    const ImGuiStyle& st = ImGui::GetStyle();
    const float lineH = ImGui::GetTextLineHeight();
    const float btnH  = ImGui::GetFrameHeight();
    const float gap   = 12.0f;

    auto centerNext = [](float itemW) {
        float w = ImGui::GetContentRegionAvail().x;
        float off = (w - itemW) * 0.5f;
        if (off > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + off);
    };
    auto centerText = [](const char* txt, bool dim, ImVec4 col) {
        float w  = ImGui::GetContentRegionAvail().x;
        float tw = ImGui::CalcTextSize(txt).x;
        float off = (w - tw) * 0.5f;
        if (off > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + off);
        if (dim) ImGui::TextDisabled("%s", txt);
        else     ImGui::TextColored(col, "%s", txt);
    };

    // The block is half the tab width; its height is the natural content height.
    // The whole block is then centered on both axes inside the tab.
    const float titleH = lineH + st.ItemSpacing.y;
    const float cardH  = st.WindowPadding.y * 2.0f
                       + lineH + st.ItemSpacing.y    // title
                       + btnH + st.ItemSpacing.y     // load button
                       + lineH + 10.0f;              // filename + slack
    const float blockH = st.WindowPadding.y * 2.0f
                       + titleH + cardH + st.ItemSpacing.y + btnH + 6.0f;

    const ImVec2 start  = ImGui::GetCursorPos();
    const ImVec2 avail  = ImGui::GetContentRegionAvail();
    const float  blockW = avail.x * 0.5f;
    float offX = (avail.x - blockW) * 0.5f;
    float offY = (avail.y - blockH) * 0.5f;
    if (offX < 0) offX = 0;
    if (offY < 0) offY = 0;
    ImGui::SetCursorPos(ImVec2(start.x + offX, start.y + offY));

    ImGui::BeginChild("DiffLoadBlock", ImVec2(blockW, blockH),
                      ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);

    centerText("Binary Diff \xE2\x80\x94 load two files to compare", true, ImVec4(1, 1, 1, 1));

    const float innerW = ImGui::GetContentRegionAvail().x;
    const float cardW  = (innerW - gap) * 0.5f;

    auto drawCard = [&](const char* id, const char* title, const char* btn, BinaryFile& bf) {
        ImGui::BeginChild(id, ImVec2(cardW, cardH), ImGuiChildFlags_Borders);
        float availY     = ImGui::GetContentRegionAvail().y;
        float innerCardW = ImGui::GetContentRegionAvail().x;
        float btnW       = innerCardW * 0.8f;
        if (btnW < 120.0f) btnW = 120.0f;
        float contentH = lineH + st.ItemSpacing.y + btnH + st.ItemSpacing.y + lineH;
        float oy = (availY - contentH) * 0.5f;
        if (oy > 0) ImGui::SetCursorPosY(ImGui::GetCursorPosY() + oy);

        centerText(title, false, theme::col::accent());
        centerNext(btnW);
        if (ImGui::Button(btn, ImVec2(btnW, 0))) openInto(bf);
        std::string fn = bf.loaded() ? baseName(bf.path()) : std::string("(none)");
        centerText(fn.c_str(), true, ImVec4(1, 1, 1, 1));
        ImGui::EndChild();
    };

    drawCard("DiffLeftCard",  "LEFT",  "Load Left...",  left_);
    ImGui::SameLine(0, gap);
    drawCard("DiffRightCard", "RIGHT", "Load Right...", right_);

    const bool ready = left_.loaded() && right_.loaded();
    ImGui::BeginDisabled(!ready);
    float cbW = innerW * 0.5f;
    centerNext(cbW);
    if (ImGui::Button("Compute Diff", ImVec2(cbW, 0))) computeDiff();
    ImGui::EndDisabled();

    ImGui::EndChild();
}

void BinaryDiffTab::renderPane(const char* id, const BinaryFile& self, const BinaryFile& other,
                               int rows, bool master, float& scrollOut, bool& hoveredOut, bool forceScroll) {
    const std::vector<uint8_t>& A = self.bytes();
    const std::vector<uint8_t>& B = other.bytes();
    const ImVec4 cDiff (0.97f, 0.45f, 0.45f, 1.0f);
    const ImVec4 cSame (0.84f, 0.86f, 0.90f, 1.0f);
    const ImVec4 cSameA(0.64f, 0.67f, 0.74f, 1.0f);
    const ImVec4 cCur  (1.00f, 0.92f, 0.45f, 1.0f);   // the currently selected change

    uint64_t curS = 0, curE = 0;
    if (curRegion_ >= 0 && curRegion_ < (int)regions_.size()) { curS = regions_[curRegion_].start; curE = regions_[curRegion_].end; }

    // Only the master pane shows a scrollbar; the follower is positioned to match.
    // A forced scroll (Prev/Next) drives both panes to the selected region.
    ImGuiWindowFlags wf = master ? 0 : ImGuiWindowFlags_NoScrollbar;
    ImGui::BeginChild(id, ImVec2(0, 0), ImGuiChildFlags_None, wf);
    if (!master || forceScroll) ImGui::SetScrollY(scrollY_);

    ui::PushMono();
    ImGuiListClipper clip;
    clip.Begin(rows);
    while (clip.Step()) {
        for (int r = clip.DisplayStart; r < clip.DisplayEnd; ++r) {
            size_t base = (size_t)r * 16;
            ImGui::TextDisabled("%08llX", (unsigned long long)base);
            ImGui::SameLine(0, 10);
            for (int c = 0; c < 16; ++c) {
                size_t idx = base + c;
                if (c) ImGui::SameLine(0, 0);
                if (idx >= A.size()) { ImGui::TextDisabled("   "); continue; }
                bool diff = (idx >= B.size()) || A[idx] != B[idx];
                bool cur  = diff && idx >= curS && idx < curE;
                ImGui::TextColored(cur ? cCur : diff ? cDiff : cSame, "%02X ", A[idx]);
            }
            ImGui::SameLine(0, 10);
            for (int c = 0; c < 16; ++c) {
                size_t idx = base + c;
                if (c) ImGui::SameLine(0, 0);
                if (idx >= A.size()) { ImGui::TextDisabled(" "); continue; }
                bool diff = (idx >= B.size()) || A[idx] != B[idx];
                bool cur  = diff && idx >= curS && idx < curE;
                char ch = (A[idx] >= 32 && A[idx] < 127) ? (char)A[idx] : '.';
                ImGui::TextColored(cur ? cCur : diff ? cDiff : cSameA, "%c", ch);
            }
        }
    }
    ui::PopMono();

    if (master && !forceScroll) scrollOut = ImGui::GetScrollY();
    hoveredOut = ImGui::IsWindowHovered();
    ImGui::EndChild();
}

} // namespace ds
