// Exercise actual navigator rendering, selection fills, scroll geometry and
// keyboard input. Synthetic LIVE ownership never attaches to a real process.
static void checkNavigatorRefinement(const std::string& path) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    Fixture f(path);
    f.tab->functions_ = {{0, "Entry", 8}, {16, "ReadFile", 8}, {64, "Finish", 8}};
    f.tab->functions_[0].chunks = {{0, 8}, {0x200000, 16}};
    ++f.tab->functionsGen_;
    f.tab->funcIndexDirty_ = true;
    f.tab->strings_.clear();
    ++f.tab->stringsGen_;
    f.tab->stringsScanned_ = true;
    f.tab->stringsScanning_ = f.tab->stringsLive_ = false;
    f.tab->analysisQueueCollapsed_ = true;
    ImVec2 size(310, 620);
    std::string visibleText;
    auto paint = [&](bool log = false) {
        frame([&] {
            f.tab->frameSnap_ = &f.detached;
            if (log) ImGui::LogToBuffer();
            f.tab->renderSidePanel(f.ctx);
            if (log) {
                visibleText = ImGui::GetCurrentContext()->LogBuffer.c_str();
                ImGui::LogFinish();
            }
        }, "Navigator refinement QA", size);
        CHECK(ImGui::GetCurrentContext()->ErrorCountCurrentFrame == 0);
    };
    auto settle = [&] { paint(); paint(); paint(); };
    auto selectedRowY = [&] {
        ImGuiWindow* functions = releaseWindow("navigator_functions");
        CHECK(functions != nullptr);
        ImGuiTable* table = functions
            ? ImGui::TableFindByID(functions->GetID("function_inspector")) : nullptr;
        CHECK(table && table->InnerWindow);
        float top = FLT_MAX, bottom = -FLT_MAX;
        if (table && table->InnerWindow) {
            const ImU32 selected = ImGui::GetColorU32(ImGuiCol_Header);
            for (const ImDrawVert& vertex : table->InnerWindow->DrawList->VtxBuffer)
                if (vertex.col == selected) {
                    top = std::min(top, vertex.pos.y);
                    bottom = std::max(bottom, vertex.pos.y);
                }
        }
        return top == FLT_MAX ? -1.0f : (top + bottom) * 0.5f;
    };

    f.tab->setStaticCursor(4); // internal instruction, not the entry address
    settle();
    const float entryY = selectedRowY();
    CHECK(entryY >= 0.0f);
    f.tab->setStaticCursor(18);
    settle();
    CHECK(selectedRowY() > entryY);
    for (uint64_t outside : {uint64_t{8}, uint64_t{24}, uint64_t{0x200010}}) {
        f.tab->setStaticCursor(outside);
        settle();
        CHECK(selectedRowY() < 0.0f);
    }
    f.tab->setStaticCursor(0x200008); // owned chunk far beyond intervening entries
    settle();
    CHECK(std::fabs(selectedRowY() - entryY) <= 1.0f);
    f.tab->cursorValid_ = false;
    settle();
    CHECK(selectedRowY() < 0.0f);
    f.tab->setStaticCursor(0); // VA zero remains a valid function entry
    settle();
    CHECK(std::fabs(selectedRowY() - entryY) <= 1.0f);
    f.tab->restoreNavigationLocation(
        {16, true, DocumentView::Hex, DocumentAddressSpace::FileOffset});
    settle(); // an offset restored from history has no mapped VA yet
    CHECK(selectedRowY() < 0.0f);
    f.tab->selectFileOffset(f.ctx, 4);
    settle(); // selection resolves the file-backed VA before highlighting
    CHECK(std::fabs(selectedRowY() - entryY) <= 1.0f);

    f.tab->setLiveCursor(16); // equal numeric addresses do not prove FILE ownership
    settle();
    CHECK(selectedRowY() < 0.0f);
    f.detached.state = DbgState::Paused;
    f.detached.pid = 77; f.detached.sessionGeneration = 123;
    DbgModule module;
    module.base = 0x10000; module.size = 128 * 4096;
    module.name = "navigator_fixture"; module.path = f.path; module.loadGeneration = 4;
    f.detached.modules.push_back(module);
    DocumentRuntimeMetadata::LiveImageIdentity identity;
    identity.valid = true; identity.pid = f.detached.pid;
    identity.sessionGeneration = f.detached.sessionGeneration;
    identity.moduleBase = module.base; identity.moduleSize = module.size;
    identity.moduleName = module.name; identity.modulePath = module.path;
    identity.moduleLoadGeneration = module.loadGeneration;
    f.ctx.setStaticDebugImageIdentity(identity);
    // Suppress first-attach auto-scan: this test renders an already chosen FILE source.
    f.tab->stringsAutoPid_ = f.detached.pid;
    f.tab->stringsAutoSessionGeneration_ = f.detached.sessionGeneration;
    f.tab->setLiveCursor(module.base + 4);
    settle();
    CHECK(std::fabs(selectedRowY() - entryY) <= 1.0f);
    ++f.detached.modules[0].loadGeneration;
    settle();
    CHECK(selectedRowY() < 0.0f);
    f.detached = DbgSnapshot{};
    f.ctx.invalidateStaticDebugImageIdentity();
    f.tab->setStaticCursor(4);

    auto checkFeedback = [&](const char* expected, bool rows, bool partial = false) {
        settle();
        ImGuiWindow* strings = releaseWindow("navigator_strings");
        CHECK(strings != nullptr);
        if (!strings) return;
        // The fixed controls and status fit without an outer scrollbar. Row
        // scrolling belongs to the table, and an empty result has no blank table.
        CHECK(strings->ScrollMax.y <= 1.0f);
        ImGuiWindow* list = releaseWindow("/strs_");
        CHECK((list != nullptr) == rows);
        if (list) CHECK(list->ScrollMax.y <= 1.0f);
        const float feedbackBottom = list ? list->Pos.y : strings->InnerRect.Max.y;
        const ImU32 disabled = ImGui::GetColorU32(ImGuiCol_TextDisabled);
        const ImU32 warning = ImGui::GetColorU32(theme::col::warn());
        bool warningDrawn = false;
        for (const ImDrawVert& vertex : strings->DrawList->VtxBuffer) {
            if (vertex.col == disabled || vertex.col == warning) {
                CHECK(vertex.pos.y >= strings->InnerRect.Min.y - 1.0f);
                CHECK(vertex.pos.y <= feedbackBottom + 1.0f);
                if (vertex.col == warning) warningDrawn = true;
            }
        }
        if (partial) CHECK(warningDrawn);
        if (f.tab->stringsScanning_) {
            bool progressDrawn = false;
            const ImU32 progress = ImGui::GetColorU32(ImGuiCol_PlotHistogram);
            // Unknown progress uses a one-second animation whose fill is empty
            // at the cycle boundary. Sample at most one further cycle (the
            // harness advances 1/60 second per frame), stopping at visible fill.
            for (int sample = 0; sample <= 60 && !progressDrawn; ++sample) {
                ImGuiWindow* progressWindow = releaseWindow("navigator_strings");
                if (progressWindow)
                    for (const ImDrawVert& vertex : progressWindow->DrawList->VtxBuffer)
                        if (vertex.col == progress && vertex.pos.y <= feedbackBottom + 1.0f)
                            progressDrawn = true;
                if (!progressDrawn && sample < 60) paint();
            }
            CHECK(progressDrawn);
        }
        paint(true);
        CHECK(visibleText.find(expected) != std::string::npos);
    };

    for (ImVec2 dimensions : {ImVec2(310, 620), ImVec2(260, 520)}) {
        size = dimensions;
        f.tab->strings_.clear(); ++f.tab->stringsGen_;
        f.tab->strFilter_[0] = 0;
        f.tab->stringsLive_ = f.tab->stringsScanning_ = f.tab->stringsTruncated_ = false;
        f.tab->stringsScanned_ = true;
        checkFeedback("No strings found in this file.", false);
        f.tab->stringsScanned_ = false;
        checkFeedback("Press Scan to extract strings.", false);
        f.tab->stringsLive_ = true;
        checkFeedback("Attach to a process, then Scan.", false);
        f.tab->stringsScanned_ = true;
        checkFeedback("No strings found in process memory.", false);
        f.tab->stringsScanning_ = f.tab->stringsScanLive_ = true;
        checkFeedback("Scanning process memory...", false);
        f.tab->stringsScanLive_ = f.tab->stringsLive_ = false;
        checkFeedback("Scanning file strings...", false);
        f.tab->stringsScanning_ = false;
        f.tab->strings_ = {{40, "Activated"}, {56, "Invalid key"}};
        ++f.tab->stringsGen_;
        std::snprintf(f.tab->strFilter_, sizeof(f.tab->strFilter_), "%s", "ACTIVATED");
        checkFeedback("1 / 2 strings", true);
        CHECK(f.tab->strVisible_ == std::vector<int>{0});
        const int* retained = f.tab->strVisible_.data();
        settle();
        CHECK(f.tab->strVisible_.data() == retained);
        std::snprintf(f.tab->strFilter_, sizeof(f.tab->strFilter_), "%s", "missing");
        checkFeedback("No matches. Clear or change the filter.", false);
        CHECK(f.tab->strVisible_.empty());
        CHECK(visibleText.find("0 / 2 strings") != std::string::npos);
        f.tab->strFilter_[0] = 0;
        f.tab->stringsTruncated_ = true;
        checkFeedback("Partial results: scan limit reached.", true, true);
        f.tab->stringsScanning_ = true;
        checkFeedback("Scanning file strings...", true, true);
    }

    f.tab->stringsScanning_ = f.tab->stringsTruncated_ = false;
    std::snprintf(f.tab->strFilter_, sizeof(f.tab->strFilter_), "%s", "missing");
    settle();
    ImGuiWindow* strings = releaseWindow("navigator_strings");
    releaseActivate(strings, "##strf");
    paint();
    paint(); // allow keyboard focus/ownership to settle before sending Escape
    CHECK(strings && ImGui::GetActiveID() == strings->GetID("##strf"));
    CHECK((ImGui::GetCurrentContext()->InputTextState.Flags & ImGuiInputTextFlags_EscapeClearsAll) != 0);
    ImGui::GetIO().AddKeyEvent(ImGuiKey_Escape, true);
    paint();
    ImGui::GetIO().AddKeyEvent(ImGuiKey_Escape, false);
    settle();
    CHECK(f.tab->strFilter_[0] == 0);
    CHECK(f.tab->strVisible_.size() == 2);
    ImGui::ClearActiveID();

    // Counts retain the full result set while production draw work stays clipped.
    constexpr size_t manyStrings = 16384;
    f.tab->strings_.clear();
    f.tab->strings_.reserve(manyStrings);
    for (size_t i = 0; i < manyStrings; ++i)
        f.tab->strings_.push_back({i * 8, "Navigator string " + std::to_string(i)});
    ++f.tab->stringsGen_;
    settle(); // logging deliberately off: logging itself disables ImGui clipping
    CHECK(f.tab->strVisible_.size() == manyStrings);
    CHECK(ImGui::GetDrawData()->TotalVtxCount < 15000);
    const int* retainedRows = f.tab->strVisible_.data();
    settle();
    CHECK(f.tab->strVisible_.data() == retainedRows);
    std::snprintf(f.tab->strFilter_, sizeof(f.tab->strFilter_), "%s", "replacement");
    settle();
    CHECK(f.tab->strVisible_.empty());
    f.tab->strings_[manyStrings / 2].text = "Replacement text";
    ++f.tab->stringsGen_; // unchanged size must still invalidate the retained filter
    settle();
    CHECK(f.tab->strVisible_ == std::vector<int>{static_cast<int>(manyStrings / 2)});

    // The optional byte-pattern navigator owns the worker's final coverage
    // summary.  Keep it visible across ordinary frames: the old synchronous
    // path put this text in a local variable, so capped/partial diagnostics were
    // silently discarded as soon as Find returned.
    f.tab->navigatorOptionalMask_ = 1u << 1; // Search is the only optional tab
    f.tab->searchHits_.clear();
    f.tab->byteSearchStatus_ =
        "2 match(es); 4.0 of 8.0 MiB read; partial coverage (1 short, 1 unreadable chunk)";
    const std::string retainedSearchStatus = f.tab->byteSearchStatus_;
    settle();
    paint(true);
    CHECK(visibleText.find(retainedSearchStatus) != std::string::npos);
    settle();
    CHECK(f.tab->byteSearchStatus_ == retainedSearchStatus);
}
