// Production UI lifecycle/navigation checks. Synthetic reports do not attach a target.
static void checkStringTraceWorkbench(const std::string& path) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    Fixture f(path);
    auto& cache = f.ctx.staticAnalysisCache();
    cache.imageRevision = f.ctx.staticBinary().imageRevision();
    cache.analysisEpoch = f.ctx.staticAnalysis().epoch();
    cache.codeData.reset();
    cache.xrefs = std::make_shared<XrefIndex>();
    cache.functions = std::make_shared<const std::vector<FuncResult>>();
    f.tab->xrefIndexSig_ = f.tab->xrefSig(f.ctx);
    auto arm = [&] {
        auto& s = f.tab->stringTrace_;
        s = {};
        s.open = s.pending = true;
        s.requestId = 81;
        s.text = "added!"; s.fileVA = 64; s.sourceVA = 64;
        s.imageSerial = f.tab->investigationImageSerial_;
        s.imageRevision = f.ctx.staticBinary().imageRevision();
        s.epoch = f.ctx.staticAnalysis().epoch();
        s.functionsGeneration = f.tab->functionsGen_;
        s.decoder = f.ctx.staticDecoderConfig();
        s.xrefs = cache.xrefs;
        s.cancellation = std::make_shared<std::atomic<bool>>(false);
    };
    auto report = std::make_shared<StringActionTraceResult>();
    report->valid = true; report->complete = false;
    report->stringVA = 64; report->stringText = "added!";
    report->status = "One candidate; review the evidence path.";
    StringActionTraceCandidate candidate;
    candidate.instructionVA = 0; candidate.functionVA = 0;
    candidate.stringRefVA = kTarget; candidate.instruction = "add dword ptr [rcx], 1";
    candidate.action = "Increment memory"; candidate.evidence = "Memory update on a path to the string reference.";
    candidate.confidence = 0.8f; candidate.suggestedName = "increment_added_candidate";
    candidate.path = {{64, 0, "String"}, {kTarget, 0, "String reference"}, {0, 0, "Candidate update"}};
    report->candidates.push_back(candidate);
    report->limitations.push_back("Static evidence does not establish runtime execution.");
    AnalysisResult delivery;
    delivery.kinds = K_StringActionTrace; delivery.epoch = f.ctx.staticAnalysis().epoch();
    delivery.stringActionTraceRequestId = 81; delivery.stringActionTrace = report;
    arm();
    auto wrong = delivery; wrong.stringActionTraceRequestId = 80;
    f.tab->adoptStringActionTraceResult(f.ctx, wrong);
    CHECK(f.tab->stringTrace_.pending && !f.tab->stringTrace_.result);
    wrong = delivery; ++wrong.epoch;
    f.tab->adoptStringActionTraceResult(f.ctx, wrong);
    CHECK(!f.tab->stringTrace_.result);
    ++f.tab->stringTrace_.functionsGeneration;
    f.tab->adoptStringActionTraceResult(f.ctx, delivery);
    CHECK(!f.tab->stringTrace_.result);
    arm(); ++f.tab->stringTrace_.imageRevision;
    f.tab->adoptStringActionTraceResult(f.ctx, delivery);
    CHECK(!f.tab->stringTrace_.result);
    arm();
    f.tab->adoptStringActionTraceResult(f.ctx, delivery);
    CHECK(f.tab->stringTrace_.result == report && !f.tab->stringTrace_.pending);
    std::string text;
    auto paint = [&] {
        frame([&] {
            ImGui::LogToBuffer();
            f.tab->renderStringActionTrace(f.ctx);
            text = GImGui->LogBuffer.c_str();
            ImGui::LogFinish();
        }, "String trace host", ImVec2(1000, 800));
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    paint(); paint();
    CHECK(text.find("added!") != std::string::npos);
    CHECK(text.find("Show instruction") != std::string::npos);
    CHECK(text.find("Open Live Assembly") != std::string::npos);
    CHECK(text.find("Name hint") != std::string::npos);
    ImGuiWindow* window = ImGui::FindWindowByName("String action trace");
    CHECK(window != nullptr);
    if (window) {
        ImGui::FocusWindow(window);
        ImGui::ActivateItemByID(window->GetID("Show instruction"));
        paint();
        CHECK(f.tab->cursorValid_ && f.tab->cursorVA_ == 0 && !f.tab->cursorLive_ && f.tab->mainView_ == 0);
    }
    // Publication changes retire the report before its address actions are shown.
    cache.xrefs = std::make_shared<XrefIndex>();
    paint();
    CHECK(!f.tab->stringTrace_.result && f.tab->stringTrace_.cancellation->load());
    // A retired address/text cannot be restamped as belonging to a new image by Retry.
    const auto oldOwner = f.tab->stringTrace_.imageSerial;
    const auto oldRequest = f.tab->stringTrace_.requestId;
    ++f.tab->investigationImageSerial_;
    paint();
    if (window) {
        ImGui::FocusWindow(window);
        ImGui::ActivateItemByID(window->GetID("Retry trace"));
        paint();
    }
    CHECK(f.tab->stringTrace_.imageSerial == oldOwner && f.tab->stringTrace_.requestId == oldRequest);
    CHECK(!f.tab->stringTrace_.pending && !f.tab->stringTrace_.waiting);
    CHECK(text.find("Select the string again") != std::string::npos);
    --f.tab->investigationImageSerial_;
    // A LIVE string with no matching attachment gives an actionable explanation.
    f.tab->requestStringActionTrace(f.ctx, 64, "added!", true);
    CHECK(f.tab->stringTrace_.open && !f.tab->stringTrace_.pending && !f.tab->stringTrace_.waiting);
    CHECK(f.tab->stringTrace_.status.find("verified mapping") != std::string::npos);
    // Exercise the real worker path with empty, complete reference evidence.
    f.tab->requestStringActionTrace(f.ctx, 64, "added!", false);
    CHECK(f.tab->stringTrace_.pending);
    for (int i = 0; i < 1000 && f.tab->stringTrace_.pending; ++i) {
        AnalysisResult value;
        while (f.ctx.staticAnalysis().tryTakeBulk(value)) f.tab->adoptStringActionTraceResult(f.ctx, value);
        if (f.tab->stringTrace_.pending) Sleep(2);
    }
    CHECK(!f.tab->stringTrace_.pending && f.tab->stringTrace_.result);
    f.tab->stringTrace_.open = false;
}
