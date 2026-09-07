static void checkSigScannerLivePatternCore() {
    constexpr uint64_t base = 0x10000000ull;
    SigPattern boundaryPattern;
    CHECK(ParseSignature("DE AD ? EF", boundaryPattern));
    {
        std::vector<uint8_t> memory(20, 0x11);
        memory[6] = 0xDE;
        memory[7] = 0xAD;
        memory[8] = 0x7C;
        memory[9] = 0xEF;
        SigScannerTab::WorkerResult result;
        uint64_t progressDone = 0;
        uint64_t progressTotal = 0;
        size_t reads = 0;
        const bool completed = SigScannerTab::scanLivePatternRanges(
            {{base, memory.size(), "fixture [rw-]"}}, boundaryPattern,
            "DE AD ? EF",
            [&](uint64_t address, void* output, size_t wanted) {
                ++reads;
                if (address < base || address - base >= memory.size()) return size_t{0};
                const size_t offset = static_cast<size_t>(address - base);
                const size_t got = (std::min)(wanted, memory.size() - offset);
                std::memcpy(output, memory.data() + offset, got);
                return got;
            },
            [] { return true; },
            [&](uint64_t done, uint64_t total) {
                progressDone = done;
                progressTotal = total;
            },
            std::stop_token{}, result, 4096, 8);
        CHECK(completed && result.error.empty());
        CHECK(reads == 3);
        CHECK(result.results.size() == 1);
        CHECK(result.results.front().address == base + 6);
        CHECK(result.results.front().sig == "DE AD ? EF");
        CHECK(result.results.front().module == "fixture [rw-]" &&
              result.results.front().live);
        CHECK(result.scopeBytes == memory.size() &&
              result.attemptedBytes == memory.size() &&
              result.scannedBytes == memory.size());
        CHECK(result.partialChunks == 0 && result.unreadableChunks == 0 &&
              !result.truncated);
        CHECK(progressDone == memory.size() && progressTotal == memory.size());
        bool partial = true;
        const std::string coverage = SigScannerTab::formatLiveCoverage(result, partial);
        CHECK(!partial && coverage.find("complete") != std::string::npos);
    }

    // The former 512 MiB budget is exercised without allocating a process-sized
    // fixture: each bounded read exposes only its first byte, and the sole match
    // lives in the first chunk beyond that old cutoff.
    {
        SigPattern bytePattern;
        CHECK(ParseSignature("AB", bytePattern));
        constexpr uint64_t oldLimit = 512ull << 20;
        constexpr uint64_t chunk = 1ull << 20;
        constexpr uint64_t rangeSize = oldLimit + chunk;
        constexpr uint64_t largeBase = 0x100000000ull;
        SigScannerTab::WorkerResult result;
        size_t reads = 0;
        const bool completed = SigScannerTab::scanLivePatternRanges(
            {{largeBase, rangeSize, "large fixture"}}, bytePattern, "AB",
            [&](uint64_t address, void* output, size_t wanted) {
                ++reads;
                if (!wanted) return size_t{0};
                static_cast<uint8_t*>(output)[0] =
                    address == largeBase + oldLimit ? 0xAB : 0;
                return size_t{1};
            },
            [] { return true; }, {}, std::stop_token{}, result, 4096,
            static_cast<size_t>(chunk));
        CHECK(completed && result.error.empty() && !result.truncated);
        CHECK(reads == 513);
        CHECK(result.scopeBytes == rangeSize && result.attemptedBytes == rangeSize);
        CHECK(result.scannedBytes == 513 && result.partialChunks == 513);
        CHECK(result.results.size() == 1 &&
              result.results.front().address == largeBase + oldLimit);
    }

    {
        SigPattern repeatedPattern;
        CHECK(ParseSignature("AA", repeatedPattern));
        std::vector<uint8_t> memory(5000, 0xAA);
        SigScannerTab::WorkerResult result;
        const bool completed = SigScannerTab::scanLivePatternRanges(
            {{base, memory.size(), "cap fixture"}}, repeatedPattern, "AA",
            [&](uint64_t address, void* output, size_t wanted) {
                const size_t offset = static_cast<size_t>(address - base);
                const size_t got = (std::min)(wanted, memory.size() - offset);
                std::memcpy(output, memory.data() + offset, got);
                return got;
            },
            [] { return true; }, {}, std::stop_token{}, result, 4096, 128);
        CHECK(completed && result.error.empty());
        CHECK(result.truncated && result.results.size() == 4096);
        CHECK(result.results.back().address == base + 4095);
        CHECK(result.attemptedBytes < result.scopeBytes);
    }

    {
        SigPattern gapPattern;
        CHECK(ParseSignature("AA BB", gapPattern));
        SigScannerTab::WorkerResult result;
        const uint64_t second = base + 0x1000;
        const bool completed = SigScannerTab::scanLivePatternRanges(
            {{base, 8, "short fixture"}, {second, 8, "zero fixture"}},
            gapPattern, "AA BB",
            [&](uint64_t address, void* output, size_t) {
                if (address == second) return size_t{0};
                const uint8_t bytes[] = {0xAA, 0xBB, 0, 0};
                std::memcpy(output, bytes, sizeof(bytes));
                return sizeof(bytes);
            },
            [] { return true; }, {}, std::stop_token{}, result, 4096, 8);
        CHECK(completed && result.error.empty() && !result.truncated);
        CHECK(result.results.size() == 1 && result.results.front().address == base);
        CHECK(result.scopeBytes == 16 && result.attemptedBytes == 16 &&
              result.scannedBytes == 4);
        CHECK(result.partialChunks == 1 && result.unreadableChunks == 1);
        result.memoryMapComplete = false;
        result.memoryMapWarning = "fixture query stopped";
        bool partial = false;
        const std::string coverage = SigScannerTab::formatLiveCoverage(result, partial);
        CHECK(partial);
        CHECK(coverage.find("4 B read from 16 B") != std::string::npos);
        CHECK(coverage.find("1 short read") != std::string::npos);
        CHECK(coverage.find("1 unreadable chunk") != std::string::npos);
        CHECK(coverage.find("memory map incomplete: fixture query stopped") !=
              std::string::npos);
    }

    {
        SigPattern bytePattern;
        CHECK(ParseSignature("AA", bytePattern));
        SigScannerTab::WorkerResult result;
        int ownershipChecks = 0;
        int reads = 0;
        const bool completed = SigScannerTab::scanLivePatternRanges(
            {{base, 1, "ownership fixture"}}, bytePattern, "AA",
            [&](uint64_t, void* output, size_t) {
                ++reads;
                static_cast<uint8_t*>(output)[0] = 0xAA;
                return size_t{1};
            },
            [&] { return ++ownershipChecks < 3; }, {}, std::stop_token{},
            result, 4096, 8);
        CHECK(completed && reads == 1 && result.results.empty());
        CHECK(result.error.find("target changed during") != std::string::npos);

        std::stop_source cancelled;
        cancelled.request_stop();
        result = {};
        reads = 0;
        CHECK(!SigScannerTab::scanLivePatternRanges(
            {{base, 1, "cancel fixture"}}, bytePattern, "AA",
            [&](uint64_t, void*, size_t) { ++reads; return size_t{1}; },
            [] { return true; }, {}, cancelled.get_token(), result, 4096, 8));
        CHECK(reads == 0 && result.results.empty());
    }
}

// Actual signature-tab rendering, immutable scan details, cached search and
// FILE handoffs. Library I/O is disabled; the one scan owns authored raw bytes.
static void checkSigScannerProductionUi(const std::string& path) {
    checkSigScannerLivePatternCore();
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    AppContext ctx;
    featureLoadRaw(ctx, path);
    SigScannerTab tab;
    tab.libraryStarted_ = tab.libraryReady_ = true;
    const auto owner = MakeDocumentResultIdentity(ctx.staticDocumentId(), ctx.staticImageGeneration(),
        ctx.staticBinary().loaded(), ctx.staticBinary().contentHash(), ctx.staticBinary().imageRevision());
    ImVec2 size(1200, 800);
    std::string text;
    auto paint = [&] {
        featureFrame([&] {
            ImGui::LogToBuffer();
            tab.render(ctx);
            text = GImGui->LogBuffer.c_str();
            ImGui::LogFinish();
        }, size);
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    auto settle = [&] { paint(); paint(); paint(); };
    auto activeWindow = [&](const char* fragment) -> ImGuiWindow* {
        for (ImGuiWindow* window : GImGui->Windows)
            if (window->LastFrameActive == ImGui::GetFrameCount() &&
                std::strstr(window->Name, fragment)) return window;
        return nullptr;
    };
    tab.requestedSub_ = 0;
    settle();
    CHECK(text.find("Find a byte pattern") != std::string::npos);
    CHECK(text.find("0 of 0 matches") != std::string::npos);

    // Publication retains read/map incompleteness independently of the 4,096
    // match cap, so a zero-result LIVE scan cannot silently look complete.
    SigScannerTab::WorkerResult liveCoverage;
    liveCoverage.request = tab.requestSerial_.load();
    liveCoverage.kind = SigScannerTab::WorkerKind::LiveScan;
    liveCoverage.livePid = 77;
    liveCoverage.liveGeneration = 88;
    liveCoverage.memoryMapComplete = false;
    liveCoverage.memoryMapWarning = "fixture map prefix only";
    liveCoverage.scopeBytes = 32;
    liveCoverage.attemptedBytes = 32;
    liveCoverage.scannedBytes = 24;
    liveCoverage.partialChunks = 1;
    tab.ready_ = std::move(liveCoverage);
    DbgSnapshot liveSnapshot;
    liveSnapshot.state = DbgState::Running;
    liveSnapshot.pid = 77;
    liveSnapshot.sessionGeneration = 88;
    tab.pollWorker(ctx, owner, liveSnapshot);
    CHECK(tab.scanCompleted_ && tab.resultsLive_ && !tab.truncated_ &&
          tab.scanPartial_);
    CHECK(tab.scanCoverageStatus_.find("24 B read from 32 B") !=
          std::string::npos);
    CHECK(tab.scanCoverageStatus_.find("memory map incomplete: fixture map prefix only") !=
          std::string::npos);
    tab.results_.clear();
    tab.resultsFilterDirty_ = true;
    tab.selectedResult_ = -1;
    tab.scanCompleted_ = false;
    tab.resultsLive_ = false;
    tab.resultsLivePid_ = 0;
    tab.resultsLiveGeneration_ = 0;
    tab.truncated_ = false;
    tab.scanPartial_ = false;
    tab.scanCoverageStatus_.clear();
    tab.progress_ = 0.0f;

    // Empty results still have visible guidance; populated rows retain VA zero,
    // full-width addresses and complete source strings for search/copy.
    tab.results_ = {{0, "48 89 ?? 24", "MODULE-A", false},
                    {16, "48 89 ?? 24", "MODULE-A skip", false},
                    {UINT64_MAX, "AA BB", "MODULE-B", false}};
    tab.staticResultsOwner_ = owner;
    tab.resultsFilterDirty_ = true;
    tab.scanCompleted_ = true;
    std::snprintf(tab.resultFilter_, sizeof(tab.resultFilter_), "module-a -SKIP");
    settle();
    CHECK(tab.visibleResults_ == std::vector<int>{0});
    CHECK(text.find("1 of 3 matches") != std::string::npos);
    const int* retainedResults = tab.visibleResults_.data();
    paint();
    CHECK(tab.visibleResults_.data() == retainedResults);

    ImGuiWindow* resultWindow = activeWindow("/res_");
    CHECK(resultWindow != nullptr);
    if (resultWindow) {
        ImGuiTable* resultTable = nullptr;
        for (int i = 0; i < GImGui->Tables.GetMapSize(); ++i) {
            ImGuiTable* table = GImGui->Tables.TryGetMapData(i);
            if (table && table->LastFrameActive == ImGui::GetFrameCount() && table->InnerWindow == resultWindow)
                resultTable = table;
        }
        CHECK(resultTable != nullptr);
        if (resultTable) {
            // BeginTable pushes its instance ID, then this row pushes integer
            // zero. EndTable already popped that scope from the child window,
            // so the window's post-render GetID(0) is a different widget ID.
            const int row = 0;
            const ImGuiID rowScope = ImHashData(&row, sizeof(row),
                ImGui::TableGetInstanceID(resultTable, resultTable->InstanceCurrent));
            ImGui::FocusWindow(resultWindow);
            ImGui::ActivateItemByID(ImHashStr("0x0", 0, rowScope));
            paint();
            CHECK(ctx.hasGotoRequest && ctx.requestedGotoVA == 0 && !ctx.requestedGotoLive);
            CHECK(ctx.requestedTab == "Binary View");
        }
    }
    std::snprintf(tab.resultFilter_, sizeof(tab.resultFilter_), "0xffffffffffffffff");
    paint();
    CHECK(tab.visibleResults_ == std::vector<int>{2});
    std::snprintf(tab.resultFilter_, sizeof(tab.resultFilter_), "not-present");
    settle();
    CHECK(tab.visibleResults_.empty());
    CHECK(text.find("No matches in this filter") != std::string::npos);
    CHECK(activeWindow("/res_") == nullptr);

    // A replaced publication with the same row count must invalidate search.
    tab.results_[0].module = "Replacement";
    tab.resultsFilterDirty_ = true;
    std::snprintf(tab.resultFilter_, sizeof(tab.resultFilter_), "replacement");
    paint();
    CHECK(tab.visibleResults_ == std::vector<int>{0});
    ++tab.staticResultsOwner_.imageRevision;
    paint();
    CHECK(tab.results_.empty() && tab.visibleResults_.empty() && !tab.scanCompleted_);

    // The immutable worker input survives changes to the editor during a scan.
    tab.resultFilter_[0] = '\0';
    std::snprintf(tab.patternInput_, sizeof(tab.patternInput_), "C3");
    tab.scan(ctx);
    std::snprintf(tab.patternInput_, sizeof(tab.patternInput_), "AA BB");
    for (int i = 0; i < 1000 && tab.workerPending_; ++i) {
        tab.pollWorker(ctx, owner, ctx.debug.snapshot());
        Sleep(2);
    }
    CHECK(!tab.workerPending_ && tab.workerStatus_.empty());
    CHECK(tab.scanCompleted_ && tab.results_.size() == ctx.staticBinary().bytes().size());
    CHECK(tab.scanPattern_ == "C3" && !tab.results_.empty() && tab.results_.front().sig == "C3");
    tab.requestedSub_ = 1;
    settle();
    CHECK(text.find("Captured byte pattern") != std::string::npos);
    CHECK(text.find("C3") != std::string::npos);
    CHECK(text.find("4096 matches") != std::string::npos);
    // StatePill draws its label directly into the draw list; ImGui's text log
    // cannot contain COMPLETE. Its underlying completion state is asserted.
    CHECK(tab.scanCompleted_ && !tab.truncated_);
    CHECK(tab.scanTarget_ == path);

    // A completed zero-match scan has a different explanation from never run.
    tab.results_.clear();
    tab.resultsFilterDirty_ = true;
    tab.requestedSub_ = 0;
    settle();
    CHECK(text.find("No byte-pattern matches") != std::string::npos);
    CHECK(activeWindow("/res_") == nullptr);

    SigScannerTab::WorkerResult functions;
    functions.request = tab.requestSerial_.load();
    functions.kind = SigScannerTab::WorkerKind::Functions;
    functions.owner = owner;
    functions.decoder = ctx.staticDecoderConfig();
    functions.functions = {{0, "Entry", 8}, {16, "ReadFile", 8}, {32, "ReadThunk", 8}};
    tab.ready_ = std::move(functions);
    tab.requestedSub_ = 3;
    std::snprintf(tab.fnFilter_, sizeof(tab.fnFilter_), "READ -thunk");
    settle();
    CHECK(tab.visibleFunctions_ == std::vector<int>{1});
    CHECK(text.find("1 of 3 functions") != std::string::npos);
    const int* retainedFunctions = tab.visibleFunctions_.data();
    paint();
    CHECK(tab.visibleFunctions_.data() == retainedFunctions);
    std::snprintf(tab.fnFilter_, sizeof(tab.fnFilter_), "0x0");
    paint();
    CHECK(tab.visibleFunctions_ == std::vector<int>{0});
    std::snprintf(tab.fnFilter_, sizeof(tab.fnFilter_), "missing");
    settle();
    CHECK(text.find("No functions match this filter") != std::string::npos);
    CHECK(activeWindow("/fns_") == nullptr);

    // Offline library access is intentional: no image or debugger is needed
    // to inspect, copy, import, export or name a saved signature.
    AppContext offline;
    SigScannerTab library;
    library.libraryStarted_ = library.libraryReady_ = true;
    SigScannerTab::Sig signature;
    signature.id = 1;
    signature.name = "Portable example";
    signature.pattern = "48 89 ?? 24";
    library.sigs_.push_back(std::move(signature));
    library.requestedSub_ = 2;
    for (int i = 0; i < 3; ++i) featureFrame([&] {
        ImGui::LogToBuffer();
        library.render(offline);
        text = GImGui->LogBuffer.c_str();
        ImGui::LogFinish();
    });
    CHECK(text.find("Portable example") != std::string::npos);
    CHECK(text.find("1 saved signatures") != std::string::npos);
    CHECK(text.find("Import library") != std::string::npos);

    // Both palettes and narrow/large-scale geometry retain the result guidance
    // and all workbench controls without a horizontal shell scrollbar.
    for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        for (float scale : {1.0f, 1.5f, 2.0f}) {
            theme::SetUiScale(scale);
            theme::ApplyTheme(palette);
            size = ImVec2(520 * scale, 800 * scale);
            tab.requestedSub_ = 0;
            settle();
            CHECK(text.find("No byte-pattern matches") != std::string::npos);
            ImGuiWindow* host = ImGui::FindWindowByName("Feature UI integration");
            CHECK(host && host->ScrollMax.x <= 1.0f);
        }
    }
    theme::SetUiScale(1.0f);
    theme::ApplyTheme(theme::ThemeId::Midnight);
    ctx.staticAnalysis().cancelAndWaitIdle();
    ctx.staticProject().hash = 0;
}
