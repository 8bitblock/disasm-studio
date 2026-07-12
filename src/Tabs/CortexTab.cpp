#include "CortexTab.h"
#include "../Core/BinaryFile.h"
#include "../Core/CFG.h"
#include "../Core/FuncAnnotate.h"
#include "../Disasm/IDisassembler.h"
#include "../Ui/Fonts.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <unordered_map>

namespace ds {

namespace {

// Project maps do not expose a mutation generation. Build an order-independent
// fingerprint so a rename/confirmed label invalidates Cortex without allocating
// and sorting a copy of every annotation on each rendered frame.
uint64_t projectKnowledgeSignature(const ProjectState& project) {
    uint64_t xorAcc = 0, sumAcc = 0;
    auto add = [&](uint8_t kind, uint64_t va, const std::string& value) {
        uint64_t item = 1469598103934665603ull;
        auto mixByte = [&item](uint8_t b) { item = (item ^ b) * 1099511628211ull; };
        mixByte(kind);
        for (unsigned shift = 0; shift != 64; shift += 8) mixByte((uint8_t)(va >> shift));
        for (unsigned char c : value) mixByte(c);
        // Two commutative accumulators make the result independent of unordered_map
        // iteration while retaining more information than a lone XOR reduction.
        item ^= item >> 33; item *= 0xff51afd7ed558ccdull;
        item ^= item >> 33; item *= 0xc4ceb9fe1a85ec53ull;
        item ^= item >> 33;
        xorAcc ^= item;
        sumAcc += item * 0x9E3779B97F4A7C15ull;
    };
    for (const auto& [va, name] : project.names) add(0, va, name);
    for (const auto& [va, label] : project.algorithmLabels) add(1, va, label);
    uint64_t h = xorAcc ^ (sumAcc + (project.names.size() * 0xD6E8FEB86659FD93ull)
                         + (project.algorithmLabels.size() * 0xA0761D6478BD642Full));
    h ^= h >> 29; h *= 0x165667919E3779F9ull; h ^= h >> 32;
    return h;
}

} // namespace

CortexInput CortexTab::inputFor(AppContext& ctx) {
    CortexInput in;
    in.bin          = &ctx.binary;
    in.effectiveArchitecture = ArchName(ctx.arch);
    in.capabilities = &caps_;
    in.algorithms   = &algos_;
    in.functions    = &funcs_;
    in.strings      = &strings_;
    in.funcInfo     = &funcInfo_;
    return in;
}

void CortexTab::analyze(AppContext& ctx) {
    if (!ctx.binary.loaded() || !ctx.disasm) return;

    // Pure load-time passes (same ones the background worker runs). Synchronous here —
    // user-triggered, and cached until the binary changes. (Follow-up: reuse
    // AppContext::analysis results instead of recomputing.)
    strings_ = ScanStringsImage(ctx.binary);
    funcs_   = AnalyzeFunctionsNamed(ctx.binary, *ctx.disasm, strings_,
                                     /*guessNames*/ true, ctx.arch).functions;

    // Analyst-owned names are authoritative and must flow into briefs, xrefs,
    // exports, and chat answers. Guesses remain useful only where no rename exists.
    for (FuncResult& f : funcs_) {
        auto it = ctx.project.names.find(f.address);
        if (it == ctx.project.names.end() || it->second.empty()) continue;
        f.name = it->second;
        f.guessed = false;
        f.reason.clear();
    }

    // Whole-program xref sweep over executable sections so AlgoScan can map each crypto
    // constant to the function(s) that reference it (drives Cortex's crypto-tagged briefs).
    xref_.clear();
    for (const auto& s : ctx.binary.sections()) {
        if (!s.executable || !s.virtualSize) continue;
        uint64_t va = ctx.binary.imageBase() + s.virtualAddress;
        size_t   avail = 0;
        const uint8_t* p = ctx.binary.ptrFromVA(va, avail);
        if (!p) continue;
        BuildXrefInto(xref_, p, std::min(avail, (size_t)s.virtualSize), va, *ctx.disasm);
    }
    FinalizeXrefIndex(xref_);

    caps_  = ScanCapabilities(ctx.binary);
    algos_ = ScanAlgorithms(ctx.binary, &xref_, &funcs_);

    // A confirmed algorithm label is also analyst-owned. Apply it to every
    // matching constant/table, and refresh xref function names after overlays.
    std::unordered_map<uint64_t, std::string> functionNames;
    functionNames.reserve(funcs_.size());
    for (const FuncResult& f : funcs_) functionNames[f.address] = f.name;
    for (AlgoMatch& a : algos_) {
        auto label = ctx.project.algorithmLabels.find(a.address);
        if (label == ctx.project.algorithmLabels.end()) {
            for (uint64_t va : a.dataVAs) {
                label = ctx.project.algorithmLabels.find(va);
                if (label != ctx.project.algorithmLabels.end()) break;
            }
        }
        if (label != ctx.project.algorithmLabels.end() && !label->second.empty())
            a.name = label->second;
        for (AlgoXref& x : a.referencedBy) {
            auto name = functionNames.find(x.funcAddress);
            if (name != functionNames.end()) x.funcName = name->second;
        }
    }

    // Per-function annotation facts (FuncAnnotate) for x86/x64 targets — this is what
    // gives each function a real "what it does" brief instead of just its guessed name.
    // Bounded so Analyze stays responsive on big binaries.
    funcInfo_.clear();
    if (ctx.arch == Arch::X86 || ctx.arch == Arch::X64) {
        AnnotateOptions opt;
        opt.x64 = ctx.arch == Arch::X64;
        // FuncAnnotate calls these lookups for many instructions. Index once so a
        // binary with tens of thousands of strings does not turn 200 CFG analyses
        // into an O(instructions * strings) render-thread stall.
        std::unordered_map<uint64_t, std::string> namesByVA;
        namesByVA.reserve(funcs_.size() + ctx.binary.imports().size());
        for (const FuncResult& fr : funcs_) namesByVA[fr.address] = fr.name;
        for (const auto& im : ctx.binary.imports())
            namesByVA[im.iatVA] = im.dll.empty() ? im.name : im.dll + "." + im.name;
        std::unordered_map<uint64_t, std::string> stringsByVA;
        stringsByVA.reserve(strings_.size());
        for (const StrResult& sr : strings_) stringsByVA[sr.address] = sr.text;

        opt.nameFor = [&namesByVA](uint64_t va) -> std::string {
            auto it = namesByVA.find(va);
            return it == namesByVA.end() ? std::string() : it->second;
        };
        opt.stringFor = [&stringsByVA](uint64_t va) -> std::string {
            auto it = stringsByVA.find(va);
            return it == stringsByVA.end() ? std::string() : it->second;
        };
        opt.looksLikeVtable = [](uint64_t) { return false; };

        int annotated = 0;
        for (const FuncResult& f : funcs_) {
            if (annotated >= 200) break;
            if (f.size && f.size < 12) continue;     // skip trivial stubs/thunks
            size_t avail = 0;
            const uint8_t* p = ctx.binary.ptrFromVA(f.address, avail);
            if (!p) continue;
            size_t n = f.size ? std::min(avail, (size_t)f.size) : std::min(avail, (size_t)4096);
            ControlFlowGraph g = BuildCFG(p, n, f.address, *ctx.disasm, 2000);
            FuncAnnotations fa = AnnotateFunction(g, opt);
            CortexFuncInfo fi;
            fi.address    = f.address;
            fi.summary    = fa.summary;
            fi.convention = fa.convention;
            for (const FnNote& note : fa.notes)
                if (note.kind == NoteKind::Pattern && !note.text.empty()) fi.patterns.push_back(note.text);
            if (!fi.summary.empty() || !fi.patterns.empty() || !fi.convention.empty())
                funcInfo_.push_back(std::move(fi));
            ++annotated;
        }
    }

    rep_          = BuildCortexReport(inputFor(ctx));
    analyzed_     = true;
    analyzedHash_ = ctx.binary.contentHash();
    analyzedRevision_ = ctx.binary.imageRevision();
    analyzedKnowledge_ = projectKnowledgeSignature(ctx.project);
    analyzedEngine_ = ctx.engine;
    analyzedArch_ = ctx.arch;
    behSel_       = rep_.behaviors.empty() ? -1 : 0;
    chat_.clear();
}

void CortexTab::ask(AppContext& ctx, const std::string& q) {
    if (q.empty() || !analyzed_) return;
    std::string a = AskCortex(rep_, inputFor(ctx), q);
    chat_.emplace_back(q, a);
    scrollChat_ = true;
}

void CortexTab::render(AppContext& ctx) {
    if (!ctx.binary.loaded()) {
        if (ui::EmptyState(DS_ICON_CODE, "No binary loaded",
                           "Open a binary and Cortex will read it: what it does, its behaviours, and a per-function brief you can chat with.",
                           "Open Binary..."))
            ctx.openBinaryDialog();
        return;
    }
    // The report is keyed to the binary's content — invalidate it if the binary changed.
    if (analyzed_ && (analyzedHash_ != ctx.binary.contentHash() ||
                      analyzedRevision_ != ctx.binary.imageRevision() ||
                      analyzedKnowledge_ != projectKnowledgeSignature(ctx.project) ||
                      analyzedEngine_ != ctx.engine || analyzedArch_ != ctx.arch))
        analyzed_ = false;

    if (ui::ToolbarIconButton(DS_ICON_LIGHTNING, analyzed_ ? "Re-analyze" : "Analyze",
                              "Read the binary: run the analyzers and reason over them"))
        analyze(ctx);
    if (analyzed_) {
        ImGui::SameLine();
        if (ui::ToolbarIconButton(DS_ICON_SAVE, "Export", "Save this Cortex report as Markdown / HTML")) {
            std::string md = RenderCortexMarkdown(rep_);
            std::string html = RenderCortexHtml(rep_);
            std::string msg;
            if (ctx.exportAnalysisFile("cortex-report", md, html, msg))
                ui::Toast(ui::ToastKind::Success, msg);
            else if (!msg.empty())
                ui::Toast(ui::ToastKind::Warn, msg);
        }
    }
    ImGui::SameLine();
    if (analyzed_) ImGui::TextDisabled("%d behaviour%s · %zu functions",
                                       (int)rep_.behaviors.size(), rep_.behaviors.size() == 1 ? "" : "s",
                                       rep_.functions.size());
    else           ImGui::TextDisabled("not analyzed");
    ImGui::Separator();

    if (!analyzed_) {
        if (ui::EmptyState(DS_ICON_CODE, "Ready to analyze",
                           "Cortex aggregates capabilities, crypto/algorithm matches, and heuristic function names into a plain-English read of this binary.",
                           "Analyze"))
            analyze(ctx);
        return;
    }

    // ---- Verdict header ----
    ImGui::PushTextWrapPos(0.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, theme::col::accent());
    ImGui::TextUnformatted(rep_.headline.c_str());
    ImGui::PopStyleColor();
    ImGui::TextWrapped("%s", rep_.verdict.c_str());
    ImGui::PopTextWrapPos();
    if (!rep_.facts.empty()) {
        std::string facts;
        for (size_t i = 0; i < rep_.facts.size(); ++i) { if (i) facts += "    ·    "; facts += rep_.facts[i]; }
        ImGui::TextColored(theme::col::muted(), "%s", facts.c_str());
    }
    ImGui::Separator();

    // ---- Middle: behaviours (left) + notable functions (right) ----
    const float scale = theme::UiScale();
    const float chatH = 190.0f * scale;
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float midH = avail.y - chatH;
    if (midH < 120.0f * scale) midH = 120.0f * scale;
    float colW = (avail.x - 8.0f * scale) * 0.5f;

    ImGui::BeginChild("cx_beh", ImVec2(colW, midH), ImGuiChildFlags_Borders);
    ImGui::TextColored(theme::col::muted(), "BEHAVIOURS");
    if (ImGui::BeginTable("cx_behtbl", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Behaviour");
        ImGui::TableSetupColumn("%", ImGuiTableColumnFlags_WidthFixed, 40.0f * scale);
        ImGui::TableSetupColumn("Evidence");
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)rep_.behaviors.size(); ++i) {
            const CortexBehavior& b = rep_.behaviors[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(b.title.c_str(), behSel_ == i, ImGuiSelectableFlags_SpanAllColumns))
                behSel_ = i;
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && !b.addresses.empty())
                ctx.gotoAddress(b.addresses.front());
            if (ImGui::IsItemHovered() && !b.explanation.empty()) ImGui::SetTooltip("%s", b.explanation.c_str());
            ImGui::TableSetColumnIndex(1);
            ImVec4 col = b.confidence > 0.80f ? theme::col::good()
                       : b.confidence > 0.60f ? theme::col::warn() : theme::col::bad();
            ImGui::TextColored(col, "%.0f", b.confidence * 100.0f);
            ImGui::TableSetColumnIndex(2);
            if (!b.specifics.empty()) {
                std::string sp;
                for (size_t k = 0; k < b.specifics.size() && k < 4; ++k) { if (k) sp += ", "; sp += b.specifics[k]; }
                ImGui::TextColored(theme::col::warn(), "%s", sp.c_str());
                if (ImGui::IsItemHovered() && !b.evidence.empty()) ImGui::SetTooltip("%s", b.evidence.c_str());
            } else {
                ImGui::TextDisabled("%s", b.evidence.c_str());
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::SameLine();
    ImGui::BeginChild("cx_hi", ImVec2(0, midH), ImGuiChildFlags_Borders);
    ImGui::TextColored(theme::col::muted(), "NOTABLE FUNCTIONS");
    if (ImGui::BeginTable("cx_hitbl", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, 150.0f * scale);
        ImGui::TableSetupColumn("What it looks like");
        ImGui::TableHeadersRow();
        for (const CortexFuncBrief& f : rep_.highlights) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushStyleColor(ImGuiCol_Text, f.guessed ? theme::col::warn() : ImGui::GetStyleColorVec4(ImGuiCol_Text));
            ImGui::PushID((void*)(uintptr_t)f.address);
            bool clicked = ImGui::Selectable(f.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns);
            ImGui::PopID();
            ImGui::PopStyleColor();
            if (clicked) ctx.gotoAddress(f.address); // VA 0 is valid for raw/ELF images
            if (ImGui::IsItemHovered() && !f.basis.empty()) ImGui::SetTooltip("%s", f.basis.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("%s", f.brief.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    // ---- Ask Cortex ----
    ImGui::BeginChild("cx_chat", ImVec2(0, 0), ImGuiChildFlags_Borders);
    ImGui::TextColored(theme::col::muted(), "ASK CORTEX");

    ImGui::BeginChild("cx_chatlog", ImVec2(0, -34.0f * scale));
    ImGui::PushTextWrapPos(0.0f);
    for (const auto& qa : chat_) {
        ImGui::TextColored(theme::col::accent(), "you: %s", qa.first.c_str());
        ImGui::TextWrapped("%s", qa.second.c_str());
        ImGui::Spacing();
    }
    if (scrollChat_) { ImGui::SetScrollHereY(1.0f); scrollChat_ = false; }
    ImGui::PopTextWrapPos();
    ImGui::EndChild();

    // Quick-ask chips.
    struct Chip { const char* label; const char* q; };
    static const Chip chips[] = {
        { "Summary",  "what does it do?" },
        { "Crypto?",  "does it use crypto?" },
        { "Network?", "what network apis does it use?" },
        { "Packed?",  "is it packed?" },
        { "Strings",  "show notable strings" },
    };
    for (int i = 0; i < (int)(sizeof(chips) / sizeof(chips[0])); ++i) {
        if (i) ImGui::SameLine();
        if (ImGui::SmallButton(chips[i].label)) ask(ctx, chips[i].q);
    }

    ImGui::SetNextItemWidth(-70.0f * scale);
    bool enter = ImGui::InputTextWithHint("##cx_ask", "ask about this binary...", input_, sizeof(input_),
                                          ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    bool send = ImGui::Button("Ask", ImVec2(60.0f * scale, 0));
    if (enter || send) {
        ask(ctx, input_);
        input_[0] = '\0';
        ImGui::SetKeyboardFocusHere(-1);
    }
    ImGui::EndChild();
}

} // namespace ds
