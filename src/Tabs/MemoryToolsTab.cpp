#include "MemoryToolsTab.h"
#include "../Core/MemCompare.h"
#include "../Ui/Fonts.h"
#include "imgui.h"
#include <algorithm>
#include <cstdio>
#include <cstring>

namespace ds {

// Keep the tab's ValueType enum in lockstep with the pure MemValType the shared
// compare helper uses (so MemTypeSize / MemAsNumber tag dispatch stays correct).
static_assert((int)MemoryToolsTab::VT_Byte  == (int)MemValType::Byte  &&
              (int)MemoryToolsTab::VT_Word  == (int)MemValType::Word  &&
              (int)MemoryToolsTab::VT_Dword == (int)MemValType::Dword &&
              (int)MemoryToolsTab::VT_Qword == (int)MemValType::Qword &&
              (int)MemoryToolsTab::VT_Float == (int)MemValType::Float &&
              (int)MemoryToolsTab::VT_Double== (int)MemValType::Double,
              "MemoryToolsTab::ValueType must match MemValType");

static const char* kValueTypes[] = { "Byte", "Word (2)", "Dword (4)", "Qword (8)", "Float", "Double" };
static const char* kScanTypes[]  = { "Exact value", "Bigger than", "Smaller than", "Changed", "Unchanged", "Unknown initial" };

static size_t typeSize(int t) { return MemTypeSize(t); }

// Parse the user's text into a little-endian needle for the chosen type.
static bool parseNeedle(int type, const char* text, bool hex, uint64_t& bitsOut, size_t& szOut) {
    szOut = typeSize(type);
    bitsOut = 0;
    if (type == MemoryToolsTab::VT_Float) {
        float f = std::strtof(text, nullptr); std::memcpy(&bitsOut, &f, 4); return true;
    }
    if (type == MemoryToolsTab::VT_Double) {
        double d = std::strtod(text, nullptr); std::memcpy(&bitsOut, &d, 8); return true;
    }
    char* end = nullptr;
    unsigned long long v = std::strtoull(text, &end, hex ? 16 : 10);
    if (end == text) return false;
    bitsOut = (uint64_t)v;
    return true;
}

static std::string formatBits(int type, uint64_t bits) {
    char b[64];
    switch (type) {
        case MemoryToolsTab::VT_Float:  { float f;  std::memcpy(&f, &bits, 4); std::snprintf(b, sizeof(b), "%g", f); break; }
        case MemoryToolsTab::VT_Double: { double d; std::memcpy(&d, &bits, 8); std::snprintf(b, sizeof(b), "%g", d); break; }
        case MemoryToolsTab::VT_Byte:   std::snprintf(b, sizeof(b), "%u", (unsigned)(bits & 0xFF)); break;
        case MemoryToolsTab::VT_Word:   std::snprintf(b, sizeof(b), "%u", (unsigned)(bits & 0xFFFF)); break;
        case MemoryToolsTab::VT_Dword:  std::snprintf(b, sizeof(b), "%u", (unsigned)(bits & 0xFFFFFFFF)); break;
        default:                        std::snprintf(b, sizeof(b), "%llu", (unsigned long long)bits); break;
    }
    return b;
}

// Compare a freshly-read value to needle/previous per scan type. Integer
// bigger/smaller comparisons honour `unsignedMode` (signed by default, so
// -1 < 0; unsigned treats the raw bits as magnitude). Routed through the pure
// MemCompare helper so the logic is unit-tested.
static bool matches(int valueType, int scanType, bool unsignedMode,
                    uint64_t cur, uint64_t prev, uint64_t needle) {
    switch (scanType) {
        case MemoryToolsTab::ST_Exact:     return cur == needle;
        case MemoryToolsTab::ST_Bigger:    return MemGreater(valueType, unsignedMode, cur, prev);
        case MemoryToolsTab::ST_Smaller:   return MemLess(valueType, unsignedMode, cur, prev);
        case MemoryToolsTab::ST_Changed:   return cur != prev;
        case MemoryToolsTab::ST_Unchanged: return cur == prev;
        case MemoryToolsTab::ST_Unknown:   return true;
    }
    return false;
}

void MemoryToolsTab::firstScan(AppContext& ctx) {
    results_.clear();
    totalFound_ = 0;
    firstScanDone_ = false;
    size_t sz = 0; uint64_t needle = 0;
    bool wantValue = (scanType_ == ST_Exact || scanType_ == ST_Bigger || scanType_ == ST_Smaller);
    if (wantValue && !parseNeedle(valueType_, scanValue_, hexInput_, needle, sz)) {
        scanStatus_ = "invalid value"; return;
    }
    sz = typeSize(valueType_);

    // Interpret raw bits per value type for ordered (bigger/smaller) comparisons,
    // honouring the signed/unsigned mode (shared with next-scan via MemCompare).
    auto asNum = [&](uint64_t bits) -> double { return MemAsNumber(valueType_, bits, unsignedMode_); };

    auto regions = ctx.debug.regions();
    std::vector<uint8_t> buf;
    const size_t kChunk = 1 << 20;        // 1 MB read window
    const size_t kCap   = 2'000'000;      // cap stored results
    size_t scannedBytes = 0;
    const size_t kByteBudget = 512ull << 20; // don't scan more than 512 MB

    for (auto& rg : regions) {
        if (!rg.read) continue;
        for (uint64_t off = 0; off < rg.size && scannedBytes < kByteBudget; off += kChunk) {
            size_t want = (size_t)std::min<uint64_t>(kChunk, rg.size - off);
            buf.resize(want);
            size_t got = ctx.debug.readMemory(rg.base + off, buf.data(), want);
            scannedBytes += got;
            if (got < sz) continue;
            for (size_t i = 0; i + sz <= got; ++i) {
                uint64_t cur = 0; std::memcpy(&cur, &buf[i], sz);
                // First "bigger/smaller than X" scan compares the current value to the
                // entered value X (the needle), Cheat-Engine style — there is no prev yet.
                bool keep = wantValue ? (scanType_ == ST_Exact   ? cur == needle
                                        : scanType_ == ST_Bigger  ? asNum(cur) > asNum(needle)
                                        : asNum(cur) < asNum(needle))
                                      : true; // Changed/Unchanged/Unknown -> capture all on first scan
                if (keep) {
                    results_.push_back({ rg.base + off + i, cur });
                    if (results_.size() >= kCap) { off = rg.size; break; }
                }
            }
        }
        if (results_.size() >= kCap) break;
    }
    // Index the results: keep them ordered by ascending address so next-scan
    // re-reads in address order and the table renders deterministically. Regions
    // already enumerate in ascending base order, but sort defensively in case the
    // OS hands them back out of order.
    if (!std::is_sorted(results_.begin(), results_.end(),
                        [](const ScanResult& a, const ScanResult& b) { return a.address < b.address; }))
        std::sort(results_.begin(), results_.end(),
                  [](const ScanResult& a, const ScanResult& b) { return a.address < b.address; });
    totalFound_ = results_.size();
    firstScanDone_ = true;
    char s[96]; std::snprintf(s, sizeof(s), "first scan: %zu result(s), %.1f MB scanned",
                              totalFound_, scannedBytes / (1024.0 * 1024.0));
    scanStatus_ = s;
}

void MemoryToolsTab::nextScan(AppContext& ctx) {
    size_t sz = typeSize(valueType_);
    uint64_t needle = 0; size_t nsz = 0;
    bool wantValue = (scanType_ == ST_Exact || scanType_ == ST_Bigger || scanType_ == ST_Smaller);
    if (scanType_ == ST_Exact && !parseNeedle(valueType_, scanValue_, hexInput_, needle, nsz)) {
        scanStatus_ = "invalid value"; return;
    }
    // results_ is kept sorted by address; walking it in order preserves that
    // ordering in `kept`, so the result index survives every re-scan.
    std::vector<ScanResult> kept;
    kept.reserve(results_.size());
    for (auto& r : results_) {
        uint64_t cur = 0;
        if (ctx.debug.readMemory(r.address, &cur, sz) < sz) continue;
        if (matches(valueType_, scanType_, unsignedMode_, cur, r.prevBits, needle))
            kept.push_back({ r.address, cur });
    }
    results_.swap(kept);
    totalFound_ = results_.size();
    char s[64]; std::snprintf(s, sizeof(s), "next scan: %zu result(s)", totalFound_);
    scanStatus_ = s;
    (void)wantValue;
}

void MemoryToolsTab::renderScanner(AppContext& ctx) {
    ImGui::SeparatorText("Memory Scanner");
    bool attached = ctx.debug.snapshot().attached();
    if (!attached) ImGui::TextDisabled("Attach a process (Communications tab) to scan live memory.");

    ImGui::SetNextItemWidth(160);
    ImGui::Combo("Value type", &valueType_, kValueTypes, IM_ARRAYSIZE(kValueTypes));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(160);
    ImGui::Combo("Scan type", &scanType_, kScanTypes, IM_ARRAYSIZE(kScanTypes));

    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##val", "value", scanValue_, sizeof(scanValue_));
    ImGui::SameLine();
    ImGui::Checkbox("Hex", &hexInput_);
    ImGui::SameLine();
    // Unsigned mode only affects ordered (bigger/smaller) integer comparisons.
    bool isInt = (valueType_ != VT_Float && valueType_ != VT_Double);
    ImGui::BeginDisabled(!isInt);
    ImGui::Checkbox("Unsigned", &unsignedMode_);
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Bigger/Smaller comparisons treat integers as unsigned "
                          "(e.g. 0xFFFFFFFF > 0). Default is signed (-1 < 0).");

    ImGui::BeginDisabled(!attached);
    if (ImGui::Button("First Scan")) firstScan(ctx);
    ImGui::SameLine();
    ImGui::BeginDisabled(!firstScanDone_);
    if (ImGui::Button("Next Scan")) nextScan(ctx);
    ImGui::SameLine();
    if (ImGui::Button("New Scan")) { firstScanDone_ = false; results_.clear(); totalFound_ = 0; scanStatus_.clear(); }
    ImGui::EndDisabled();
    ImGui::EndDisabled();

    if (!scanStatus_.empty()) ImGui::TextDisabled("%s", scanStatus_.c_str());
    ImGui::Text("Showing %d of %zu", (int)std::min<size_t>(results_.size(), 1000), totalFound_);

    ui::PushMono();
    if (ImGui::BeginTable("scanres", 2,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
            ImVec2(0, ImGui::GetContentRegionAvail().y - ImGui::GetTextLineHeightWithSpacing()))) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 180);
        ImGui::TableSetupColumn("Value");
        ImGui::TableHeadersRow();
        // Clip to the visible rows: a large result set (capped at 1000) otherwise
        // does 1000 cross-process readMemory() calls + 1000 string allocations
        // every frame even though only a screenful is shown.
        size_t shown = std::min<size_t>(results_.size(), 1000);
        ImGuiListClipper clip;
        clip.Begin((int)shown);
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                auto& r = results_[(size_t)i];
                uint64_t cur = 0;
                ctx.debug.readMemory(r.address, &cur, typeSize(valueType_));
                ImGui::TableNextRow();
                ImGui::PushID(i);
                ImGui::TableSetColumnIndex(0);
                char al[24]; std::snprintf(al, sizeof(al), "0x%llX", (unsigned long long)r.address);
                if (ImGui::Selectable(al, false, ImGuiSelectableFlags_SpanAllColumns)) {}
                if (ImGui::BeginPopupContextItem("rc")) {
                    if (ImGui::MenuItem("Add to address table"))
                        table_.push_back({ true, "scan result", r.address, valueType_, formatBits(valueType_, cur), false });
                    ImGui::EndPopup();
                }
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(formatBits(valueType_, cur).c_str());
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
    ui::PopMono();
    ImGui::TextDisabled("Right-click a result to add it to the address table.");
}

void MemoryToolsTab::renderViewerEditor(AppContext& ctx) {
    ImGui::SeparatorText("Viewer / Editor");
    bool attached = ctx.debug.snapshot().attached();
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##va", "address (hex)", viewAddr_, sizeof(viewAddr_));
    unsigned long long base = 0; std::sscanf(viewAddr_, "%llx", &base);

    ImGui::BeginChild("memdump", ImVec2(0, 150), ImGuiChildFlags_Borders);
    if (!attached) {
        ImGui::TextDisabled("Attach a process to read memory.");
    } else {
        ui::PushMono();
        uint8_t row[16];
        for (int r = 0; r < 8; ++r) {
            uint64_t addr = base + r * 16;
            size_t got = ctx.debug.readMemory(addr, row, 16);
            char line[128]; int o = 0;
            o += std::snprintf(line + o, sizeof(line) - o, "%012llX  ", (unsigned long long)addr);
            for (int c = 0; c < 16; ++c)
                o += (c < (int)got) ? std::snprintf(line + o, sizeof(line) - o, "%02X ", row[c])
                                    : std::snprintf(line + o, sizeof(line) - o, "-- ");
            o += std::snprintf(line + o, sizeof(line) - o, " ");
            for (int c = 0; c < (int)got; ++c) {
                char ch = (row[c] >= 32 && row[c] < 127) ? (char)row[c] : '.';
                o += std::snprintf(line + o, sizeof(line) - o, "%c", ch);
            }
            ImGui::TextUnformatted(line);
        }
        ui::PopMono();
    }
    ImGui::EndChild();
    ImGui::TextDisabled("Edit values from the address table below; writes go through to the process.");
}

void MemoryToolsTab::renderBrowser(AppContext& ctx) {
    ImGui::SeparatorText("Memory Browser");
    bool attached = ctx.debug.snapshot().attached();
    if (!attached) { ImGui::TextDisabled("Attach a process to enumerate memory regions."); return; }

    auto regions = ctx.debug.regions();
    ImGui::Text("%d committed region(s)", (int)regions.size());
    ImGui::BeginChild("regtree", ImVec2(0, ImGui::GetContentRegionAvail().y), ImGuiChildFlags_Borders);
    for (size_t i = 0; i < regions.size() && i < 4000; ++i) {
        auto& rg = regions[i];
        char prot[8]; std::snprintf(prot, sizeof(prot), "%c%c%c",
            rg.read ? 'R' : '-', rg.write ? 'W' : '-', rg.exec ? 'X' : '-');
        char lbl[96]; std::snprintf(lbl, sizeof(lbl), "0x%llX  %8llu KB  %s",
            (unsigned long long)rg.base, (unsigned long long)(rg.size / 1024), prot);
        if (ImGui::Selectable(lbl)) std::snprintf(viewAddr_, sizeof(viewAddr_), "%llX", (unsigned long long)rg.base);
    }
    ImGui::EndChild();
}

void MemoryToolsTab::renderAddressTable(AppContext& ctx) {
    ImGui::SeparatorText("Address Table");
    bool attached = ctx.debug.snapshot().attached();

    // Freeze loop: rewrite frozen entries each frame.
    if (attached) {
        for (auto& e : table_) {
            if (!e.frozen) continue;
            uint64_t bits = 0; size_t sz = 0;
            if (parseNeedle(e.type, e.value.c_str(), false, bits, sz))
                ctx.debug.writeMemory(e.address, &bits, sz);
        }
    }

    if (ImGui::BeginTable("addrtbl", 6,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 30);
        ImGui::TableSetupColumn("Description");
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 160);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 110);
        ImGui::TableSetupColumn("Freeze", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)table_.size(); ++i) {
            auto& e = table_[i];
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(0); ImGui::Checkbox("##on", &e.active);
            ImGui::TableSetColumnIndex(1);
            { char d[64]; std::snprintf(d, sizeof(d), "%s", e.desc.c_str());
              ImGui::SetNextItemWidth(-1); if (ImGui::InputText("##d", d, sizeof(d))) e.desc = d; }
            ImGui::TableSetColumnIndex(2); ImGui::Text("0x%llX", (unsigned long long)e.address);
            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(kValueTypes[e.type]);
            ImGui::TableSetColumnIndex(4);
            // Show live value when attached & not frozen; allow editing -> write-through.
            char buf[64];
            if (attached && !e.frozen) {
                uint64_t cur = 0; ctx.debug.readMemory(e.address, &cur, typeSize(e.type));
                e.value = formatBits(e.type, cur);
            }
            std::snprintf(buf, sizeof(buf), "%s", e.value.c_str());
            ImGui::SetNextItemWidth(-1);
            if (ImGui::InputText("##v", buf, sizeof(buf), ImGuiInputTextFlags_EnterReturnsTrue)) {
                e.value = buf;
                if (attached) { uint64_t bits = 0; size_t sz = 0;
                                if (parseNeedle(e.type, buf, false, bits, sz)) ctx.debug.writeMemory(e.address, &bits, sz); }
            }
            ImGui::TableSetColumnIndex(5); ImGui::Checkbox("##fz", &e.frozen);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::SetNextItemWidth(160);
    ImGui::InputTextWithHint("##newaddr", "address (hex)", newAddr_, sizeof(newAddr_));
    ImGui::SameLine();
    if (ImGui::Button("Add Row")) {
        unsigned long long a = 0; std::sscanf(newAddr_, "%llx", &a);
        table_.push_back({ true, "entry", a, valueType_, "0", false });
        newAddr_[0] = '\0';
    }
}

void MemoryToolsTab::render(AppContext& ctx) {
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float colW = avail.x * 0.5f;

    ImGui::BeginChild("mt_left", ImVec2(colW - 4, avail.y * 0.6f), ImGuiChildFlags_Borders);
    renderScanner(ctx);
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("mt_right", ImVec2(0, avail.y * 0.6f), ImGuiChildFlags_Borders);
    renderViewerEditor(ctx);
    renderBrowser(ctx);
    ImGui::EndChild();

    ImGui::BeginChild("mt_table", ImVec2(0, 0), ImGuiChildFlags_Borders);
    renderAddressTable(ctx);
    ImGui::EndChild();
}

} // namespace ds
