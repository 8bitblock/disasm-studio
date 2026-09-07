// Production-object value-origin UI contracts; synthetic reports never execute a target.
static void checkValueOriginWorkbench(const std::string& path) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    Fixture f(path);
    f.tab->functions_ = {{kTarget, "origin_fixture", 16}};
    ++f.tab->functionsGen_; f.tab->funcIndexDirty_ = true;
    auto arm = [&] {
        auto& state = f.tab->valueOrigin_;
        state.requestId = 71;
        state.imageSerial = f.tab->investigationImageSerial_;
        state.imageRevision = f.ctx.staticBinary().imageRevision();
        state.epoch = f.ctx.staticAnalysis().epoch();
        state.functionsGeneration = f.tab->functionsGen_;
        state.decoder = f.ctx.staticDecoderConfig();
        state.pending = true; state.idleFrames = 0;
        state.cancellation = std::make_shared<std::atomic<bool>>(false);
        state.result.reset(); state.highlighted.clear();
    };
    auto value = std::make_shared<ValueOriginResult>();
    value->valid = true; value->complete = false;
    value->instructionVA = kTarget + 4; value->registerName = "eax";
    value->status = "Partial register dependencies; review boundaries.";
    value->sources = {{0, "mov eax, 1", "definition at address zero"},
                      {kTarget, "add eax, 2", "possible transformation"}};
    value->boundaries = {{ValueOriginBoundaryKind::Join, kTarget + 2, "Alternative predecessor paths."}};
    AnalysisResult delivery;
    delivery.kinds = K_ValueOrigin; delivery.epoch = f.ctx.staticAnalysis().epoch();
    delivery.valueOriginRequestId = 71; delivery.valueOrigin = value;
    arm();
    auto wrong = delivery; wrong.valueOriginRequestId = 70;
    f.tab->adoptValueOriginResult(f.ctx, wrong);
    CHECK(f.tab->valueOrigin_.pending && !f.tab->valueOrigin_.result);
    wrong = delivery; wrong.epoch = delivery.epoch - 1;
    f.tab->adoptValueOriginResult(f.ctx, wrong);
    CHECK(f.tab->valueOrigin_.pending && !f.tab->valueOrigin_.result);
    ++f.tab->valueOrigin_.imageRevision;
    f.tab->adoptValueOriginResult(f.ctx, delivery);
    CHECK(!f.tab->valueOrigin_.result);
    arm(); ++f.tab->valueOrigin_.functionsGeneration;
    f.tab->adoptValueOriginResult(f.ctx, delivery);
    CHECK(!f.tab->valueOrigin_.result);
    arm(); f.tab->valueOrigin_.decoder.arch = Arch::X86;
    f.tab->adoptValueOriginResult(f.ctx, delivery);
    CHECK(!f.tab->valueOrigin_.result);
    arm();
    f.tab->adoptValueOriginResult(f.ctx, delivery);
    CHECK(!f.tab->valueOrigin_.pending && f.tab->valueOrigin_.result == value);
    CHECK(f.tab->valueOriginHighlights(f.ctx, 0));
    CHECK(f.tab->valueOriginHighlights(f.ctx, kTarget));
    CHECK(!f.tab->valueOriginHighlights(f.ctx, kTarget + 2));
    ++f.tab->investigationImageSerial_;
    CHECK(!f.tab->valueOriginHighlights(f.ctx, kTarget));
    --f.tab->investigationImageSerial_;
    f.tab->functionsDirty_ = true;
    CHECK(!f.tab->valueOriginHighlights(f.ctx, kTarget));
    f.tab->functionsDirty_ = false;
    f.tab->valueOrigin_.reveal = true;
    std::string text;
    auto paint = [&] {
        frame([&] {
            ImGui::LogToBuffer();
            f.tab->renderValueOriginInspector(f.ctx);
            text = GImGui->LogBuffer.c_str();
            ImGui::LogFinish();
        }, "Value origins UI", ImVec2(600, 800));
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    paint(); paint();
    CHECK(!f.tab->valueOrigin_.reveal);
    CHECK(text.find("Register before selected instruction") != std::string::npos);
    CHECK(text.find("Trace value") != std::string::npos);
    CHECK(text.find("Uncertainty / scope boundaries") != std::string::npos);
    ImGuiWindow* sourceWindow = nullptr;
    for (ImGuiWindow* window : GImGui->Windows)
        if (window->LastFrameActive == ImGui::GetFrameCount() &&
            std::strstr(window->Name, "Value origins UI") && std::strstr(window->Name, "sources")) sourceWindow = window;
    CHECK(sourceWindow != nullptr);
    if (sourceWindow) {
        ImGui::FocusWindow(sourceWindow);
        ImGui::ActivateItemByID(ImHashStr("0x0", 0, sourceWindow->GetID(0)));
        paint();
        CHECK(f.tab->cursorValid_ && f.tab->cursorVA_ == 0 && f.tab->mainView_ == 0);
        CHECK(f.tab->valueOrigin_.result == value && f.tab->valueOrigin_.result->instructionVA == kTarget + 4);
    }
    // A late worker result is still adoptable after one idle inspector frame.
    arm(); f.tab->valueOrigin_.reveal = true;
    paint(); CHECK(f.tab->valueOrigin_.pending);
    f.tab->adoptValueOriginResult(f.ctx, delivery);
    CHECK(f.tab->valueOrigin_.result == value && !f.tab->valueOrigin_.pending);
    f.ctx.staticAnalysis().bumpEpoch();
    CHECK(!f.tab->valueOriginHighlights(f.ctx, 0));
    paint();
    CHECK(!f.tab->valueOrigin_.result && f.tab->valueOrigin_.cancellation->load());

    // The real Assembly row menu exposes the register-value action.
    f.tab->setStaticCursor(kTarget);
    CHECK(f.clickRow(kTarget, false, ImGuiMouseButton_Right));
    f.assemblyFrame();
    CHECK(!GImGui->OpenPopupStack.empty());
    if (!GImGui->OpenPopupStack.empty()) {
        ImGuiWindow* popup = GImGui->OpenPopupStack.back().Window;
        CHECK(popup != nullptr);
        if (popup) {
            ImGui::FocusWindow(popup);
            ImGui::ActivateItemByID(popup->GetID("Where did this value come from?"));
            f.assemblyFrame(); f.assemblyFrame();
            CHECK(GImGui->OpenPopupStack.Size >= 2);
        }
    }
    ImGui::ClosePopupsOverWindow(nullptr, false);
}
