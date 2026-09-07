// Exercise the actual cursor-following Xrefs panel and publication path. The
// existing fixture supplies a bounded raw image and headless ImGui frame.
static AnalysisResult referenceResult(Fixture& f);

static void checkStaticXrefWorkflow(const std::string& path) {
    Fixture f(path);
    auto result = referenceResult(f);
    result.xref->clear();
    result.xref->classificationApplied = true;
    result.xref->classificationScopeDigest = result.codeData->scopeDigest;
    result.xref->toTarget[0] = {kTarget, kTarget + 2, kTarget + 4, kTarget + 6};
    result.xref->accessOf[kTarget] = 1;     // writer
    result.xref->accessOf[kTarget + 2] = 0; // reader
    result.xref->accessOf[kTarget + 4] = 2; // address taken
    result.xref->toTarget[16] = {kTarget + 8}; // branch-only target
    result.xref->acceptedEdges = 5;
    CHECK(f.tab->adoptStaticXrefResult(f.ctx, result));
    f.tab->setStaticCursor(0);

    std::string text;
    auto render = [&] {
        ImGui::LogToBuffer();
        f.tab->renderXrefsTab(f.ctx);
        text = ImGui::GetCurrentContext()->LogBuffer.c_str();
        ImGui::LogFinish();
    };
    frame(render);
    CHECK(text.find("5 reference edge(s) indexed") != std::string::npos);
    CHECK(text.find("References to 0x0") != std::string::npos);
    CHECK(text.find("Writers (1)") != std::string::npos);
    CHECK(text.find("Readers (1)") != std::string::npos);
    CHECK(text.find("Address taken (1)") != std::string::npos);
    CHECK(text.find("Branches/calls (1)") != std::string::npos);
    CHECK(f.tab->xrefPanelGroups_[0].valid && f.tab->xrefPanelGroups_[0].target == 0);
    CHECK(f.tab->xrefPanelGroups_[0].writers == std::vector<uint64_t>{kTarget});

    // A different cursor has different groups; an empty target must not show
    // the previous target's rows, and a branch-only target remains a flat list.
    f.tab->setStaticCursor(24);
    frame(render);
    CHECK(text.find("no references found") != std::string::npos);
    CHECK(text.find("Writers") == std::string::npos);
    f.tab->setStaticCursor(16);
    frame(render);
    CHECK(text.find("1 reference(s)") != std::string::npos);
    CHECK(text.find("Writers") == std::string::npos);
    CHECK(text.find("Branches/calls") == std::string::npos);
    CHECK(f.tab->xrefPanelGroups_[0].branches == std::vector<uint64_t>{kTarget + 8});

    // Cursor and enclosing-function groups need independent retained entries.
    BinaryViewTab::Func function{};
    function.address = 0; function.size = 32; function.name = "xref_owner";
    f.tab->functions_ = {function}; f.tab->funcIndexDirty_ = true;
    frame(render);
    CHECK(text.find("References to enclosing function to 0x0") != std::string::npos);
    CHECK(f.tab->xrefPanelGroups_[0].target == 16);
    CHECK(f.tab->xrefPanelGroups_[1].valid && f.tab->xrefPanelGroups_[1].target == 0);
    CHECK(f.tab->xrefPanelGroups_[1].writers == std::vector<uint64_t>{kTarget});
    const auto* retainedWriters = f.tab->xrefPanelGroups_[1].writers.data();
    const auto retainedSerial = f.tab->xrefPanelResultSerial_;
    for (int i = 0; i < 3; ++i) frame(render);
    CHECK(f.tab->xrefPanelGroups_[1].writers.data() == retainedWriters);
    CHECK(f.tab->xrefPanelResultSerial_ == retainedSerial);

    // Owned noncontiguous chunks can be far from the entry. Do not suppress
    // their enclosing-function references through an arbitrary distance cap.
    f.tab->functions_[0].chunks = {{0, 32}, {0x200000, 16}};
    f.tab->funcIndexDirty_ = true;
    f.tab->setStaticCursor(0x200000);
    frame(render);
    CHECK(text.find("References to enclosing function to 0x0") != std::string::npos);
    f.tab->setStaticCursor(16);

    // An explicit rebuild can publish different references at exactly the same
    // image/epoch/decoder signature. Adoption, not target/signature alone, must
    // retire both cached groups and the total count, including partial evidence.
    const uint64_t oldSignature = f.tab->xrefIndexSig_;
    auto replacement = referenceResult(f);
    replacement.xref->toTarget[0] = {kTarget + 10};
    replacement.xref->accessOf[kTarget + 10] = 0;
    replacement.xref->acceptedEdges = 1;
    replacement.xref->complete = false;
    replacement.xref->stopReason = XrefStopReason::EdgeBudget;
    CHECK(f.tab->adoptStaticXrefResult(f.ctx, replacement));
    CHECK(f.tab->xrefIndexSig_ == oldSignature);
    frame(render);
    CHECK(text.find("1 reference edge(s) indexed") != std::string::npos);
    CHECK(text.find("Partial xref index") != std::string::npos);
    CHECK(text.find("Writers") == std::string::npos);
    CHECK(f.tab->xrefPanelResultSerial_ != retainedSerial);
    CHECK(!f.tab->xrefPanelGroups_[0].valid); // cursor 16 is no longer referenced
    CHECK(f.tab->xrefPanelGroups_[1].readers == std::vector<uint64_t>{kTarget + 10});

    // Exercise a hub and many unrelated indexed targets without logging all
    // clipped source rows. Normal repeated frames retain the built partitions.
    auto large = referenceResult(f);
    large.xref->toTarget.clear(); large.xref->accessOf.clear();
    constexpr size_t hubSources = 32768;
    auto& sources = large.xref->toTarget[0];
    sources.reserve(hubSources);
    for (size_t i = 0; i < hubSources; ++i) {
        const uint64_t address = kTarget + i * 2;
        sources.push_back(address);
        large.xref->accessOf[address] = static_cast<uint8_t>(i % 3);
    }
    for (uint64_t target = 0x100000; target < 0x102000; ++target)
        large.xref->toTarget[target] = {kTarget};
    large.xref->acceptedEdges = hubSources + 8192;
    CHECK(f.tab->adoptStaticXrefResult(f.ctx, large));
    f.tab->setStaticCursor(0);
    frame([&] { f.tab->renderXrefsTab(f.ctx); });
    CHECK(f.tab->xrefPanelEdgeCount_ == hubSources + 8192);
    CHECK(f.tab->xrefPanelGroups_[0].writers.size() == 10923);
    CHECK(f.tab->xrefPanelGroups_[0].readers.size() == 10923);
    CHECK(f.tab->xrefPanelGroups_[0].takers.size() == 10922);
    const auto* hubWriters = f.tab->xrefPanelGroups_[0].writers.data();
    for (int i = 0; i < 4; ++i) frame([&] { f.tab->renderXrefsTab(f.ctx); });
    CHECK(f.tab->xrefPanelGroups_[0].writers.data() == hubWriters);

    // A stale epoch does not expose the previously cached result while its
    // replacement is being requested. A valid empty publication retires it.
    f.ctx.staticAnalysis().bumpEpoch();
    frame(render);
    CHECK(text.find("Building cross-reference index") != std::string::npos ||
          text.find("unavailable or was canceled") != std::string::npos);
    CHECK(text.find("Writers") == std::string::npos);
    f.ctx.staticAnalysis().cancelAndWaitIdle();
    // The service's cancel barrier advances the epoch. Model a terminal request
    // in that current context; normal epoch changes independently allow a new
    // request. Exhausting one request must not itself schedule endless retries.
    f.tab->xrefRequestedSig_ = f.tab->xrefSig(f.ctx);
    frame(render);
    CHECK(text.find("unavailable or was canceled") != std::string::npos);
    CHECK(text.find("Retry xref analysis") != std::string::npos);
    CHECK(!f.ctx.staticAnalysis().bulkPending());
    const uint64_t canceledRequest = f.tab->xrefRequestedSig_;
    frame(render);
    CHECK(f.tab->xrefRequestedSig_ == canceledRequest); // no automatic retry loop
    CHECK(!f.ctx.staticAnalysis().bulkPending());
    ImGuiWindow* window = ImGui::FindWindowByName("Listing integration");
    CHECK(window != nullptr);
    if (window) {
        ImGui::FocusWindow(window);
        ImGui::ActivateItemByID(window->GetID("Retry xref analysis"));
    }
    frame(render);
    CHECK(f.tab->xrefRequestedSig_ == ~uint64_t{0});
    frame(render);
    CHECK(f.tab->xrefRequestedSig_ == f.tab->xrefSig(f.ctx));
    f.ctx.staticAnalysis().cancelAndWaitIdle();
    auto empty = referenceResult(f);
    empty.xref->toTarget.clear(); empty.xref->acceptedEdges = 0;
    CHECK(f.tab->adoptStaticXrefResult(f.ctx, empty));
    frame(render);
    CHECK(text.find("0 reference edge(s) indexed") != std::string::npos);
    CHECK(text.find("no references found") != std::string::npos);
    CHECK(f.tab->xrefPanelGroups_[0].writers.empty());
}
