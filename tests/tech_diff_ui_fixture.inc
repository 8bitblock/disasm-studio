// Production tab rendering with immutable synthetic findings/results. No process
// is attached and the Binary Diff worker receives no comparison request here.
static void checkTechDiffProductionUi(const std::string& path) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    AppContext ctx;
    featureLoadRaw(ctx, path);
    const float scale = theme::UiScale();
    auto activeWindow = [](const char* fragment) -> ImGuiWindow* {
        for (ImGuiWindow* window : ImGui::GetCurrentContext()->Windows)
            if (window->Active && std::strstr(window->Name, fragment)) return window;
        return nullptr;
    };
    auto identity = [&] {
        return MakeDocumentResultIdentity(ctx.staticDocumentId(), ctx.staticImageGeneration(),
            ctx.staticBinary().loaded(), ctx.staticBinary().contentHash(), ctx.staticBinary().imageRevision());
    };

    BinaryTechTab tech;
    tech.owner_ = identity();
    tech.scanned_ = true;
    tech.selected_ = 0;
    Capability network;
    network.name = "Network requests";
    network.category = "network";
    network.detail = "WinHTTP imports provide the request capability.";
    network.analyzer = "TechScan";
    network.confidence = 0.93f;
    network.address = 0;
    network.addressValid = true;
    network.addresses = {0, 16};
    network.hitCount = 3;
    Capability crypto = network;
    crypto.name = "AES constants";
    crypto.category = "crypto";
    crypto.detail = "Recognized constant table in the image.";
    crypto.analyzer = "AlgoScan";
    crypto.confidence = 0.60f;
    crypto.address = 16;
    crypto.addresses = {16};
    tech.caps_ = {network, crypto};
    std::string logged;
    ImVec2 size(1200.0f * scale, 820.0f * scale);
    auto paintTech = [&](bool log = false) {
        featureFrame([&] {
            if (log) ImGui::LogToBuffer();
            tech.render(ctx);
            if (log) {
                logged = ImGui::GetCurrentContext()->LogBuffer.c_str();
                ImGui::LogFinish();
            }
        }, size);
        CHECK(ImGui::GetCurrentContext()->ErrorCountCurrentFrame == 0);
    };
    paintTech(); paintTech(); paintTech(true);
    CHECK(tech.visible_.size() == 2);
    CHECK(tech.selected_ == 0);
    CHECK(logged.find("0x0") != std::string::npos);
    CHECK(logged.find("3 observed occurrences; 2 mapped locations") != std::string::npos);
    CHECK(logged.find("heuristic") != std::string::npos);
    CHECK(SameDocumentResultImage(tech.previewOwner_, identity()));
    CHECK(tech.previewAddress_ == 0);
    CHECK(!tech.previewLines_.empty());
    auto* list = activeWindow("/caplist_");
    auto* detail = activeWindow("/capdetail_");
    CHECK(list && detail);
    if (list && detail) CHECK(detail->Pos.x >= list->Pos.x + list->Size.x);

    // Query both evidence and analyzer provenance; a filtered selection must
    // follow the visible result, and zero matches cannot leave stale details.
    std::snprintf(tech.filter_, sizeof(tech.filter_), "%s", "aLgOsCaN");
    paintTech(); paintTech(true);
    CHECK(tech.visible_.size() == 1 && tech.selected_ == 1);
    CHECK(tech.previewAddress_ == 16);
    CHECK(logged.find("AES constants") != std::string::npos);
    CHECK(logged.find("WinHTTP imports") == std::string::npos);
    std::snprintf(tech.filter_, sizeof(tech.filter_), "%s", "does not occur");
    paintTech(); paintTech(true);
    CHECK(tech.visible_.empty() && tech.selected_ == -1);
    CHECK(logged.find("No matching capabilities") != std::string::npos);
    CHECK(activeWindow("/capdetail_") == nullptr);
    std::snprintf(tech.filter_, sizeof(tech.filter_), "%s", "WINHTTP");
    paintTech(); paintTech();
    CHECK(tech.visible_.size() == 1 && tech.selected_ == 0);

    // The narrow layout gives both surfaces their own visible space and retains
    // access to long disassembly lines through a horizontal preview scrollbar.
    size = ImVec2(560.0f * scale, 850.0f * scale);
    paintTech(); paintTech(); paintTech();
    list = activeWindow("/caplist_");
    detail = activeWindow("/capdetail_");
    CHECK(list && detail);
    if (list && detail) {
        CHECK(detail->Pos.y >= list->Pos.y + list->Size.y);
        CHECK(detail->Size.x > 450.0f * scale);
        CHECK(detail->Size.y > 120.0f * scale);
    }
    auto* preview = activeWindow("/##tech_code_");
    CHECK(preview && (preview->Flags & ImGuiWindowFlags_HorizontalScrollbar));
    CHECK(ctx.setStaticDecoderConfiguration(Engine::Zydis, Arch::X86));
    paintTech(); paintTech();
    CHECK(tech.previewDecoder_ == ctx.staticDecoderConfig());
    CHECK(tech.previewDecoder_.arch == Arch::X86);
    const uint8_t replacement = 0xC3;
    CHECK(ctx.writeStaticImage(0, &replacement, 1) == 1);
    paintTech(); paintTech(true);
    CHECK(!tech.scanned_ && tech.caps_.empty() && tech.visible_.empty());
    CHECK(!tech.previewOwner_);
    CHECK(logged.find("Not scanned yet") != std::string::npos);

    BinaryDiffTab diff;
    diff.computed_ = true;
    diff.semanticMode_ = true;
    diff.semanticComputed_ = true;
    diff.semanticLeft_.emplace();
    diff.semanticRight_.emplace();
    diff.semanticDiff_.complete = true;
    for (int i = 0; i < 3; ++i) {
        SemanticFunction function;
        function.address = static_cast<uint64_t>(i) * 16;
        function.name = i == 0 ? "Startup" : i == 1 ? "ReadRequest" : "RenderView";
        SemanticInstruction instruction;
        instruction.address = function.address;
        instruction.length = 1;
        instruction.mnemonic = "ret";
        instruction.display = "ret";
        function.instructions.push_back(instruction);
        diff.semanticLeft_->functions.push_back(function);
        diff.semanticRight_->functions.push_back(function);
        SemanticFunctionMatch match;
        match.leftIndex = match.rightIndex = static_cast<size_t>(i);
        match.leftAddress = match.rightAddress = function.address;
        match.confidence = 0.95f;
        match.evidence = i == 1 ? "Matching request call neighborhood" : "Matching instruction semantics";
        if (i == 1) {
            InstructionEditHunk hunk;
            hunk.leftCount = hunk.rightCount = 1;
            match.hunks.push_back(hunk);
        }
        diff.semanticDiff_.matched.push_back(match);
    }
    diff.semanticDiff_.added.push_back({0, 0x100, "NewRequest"});
    diff.semanticDiff_.removed.push_back({0, 0x200, "OldRequest"});
    diff.semanticSelectedMatch_ = 0;
    size = ImVec2(1200.0f * scale, 850.0f * scale);
    ImGuiID semanticBarId = 0;
    auto paintSemantic = [&](bool log = false) {
        featureFrame([&] {
            semanticBarId = ImGui::GetID("SemanticLists");
            if (log) ImGui::LogToBuffer();
            diff.renderSemantic(ctx);
            if (log) {
                logged = ImGui::GetCurrentContext()->LogBuffer.c_str();
                ImGui::LogFinish();
            }
        }, size);
        CHECK(ImGui::GetCurrentContext()->ErrorCountCurrentFrame == 0);
    };
    paintSemantic(); paintSemantic(); paintSemantic(true);
    CHECK(diff.semanticVisibleMatches_.size() == 3);
    CHECK(logged.find("Baseline instructions") != std::string::npos);
    std::snprintf(diff.semanticFilter_, sizeof(diff.semanticFilter_), "%s", "rEqUeSt");
    paintSemantic(); paintSemantic(true);
    CHECK(diff.semanticVisibleMatches_.size() == 1 && diff.semanticSelectedMatch_ == 1);
    CHECK(diff.semanticVisibleAdded_.size() == 1 && diff.semanticVisibleRemoved_.size() == 1);
    CHECK(logged.find("Matching request call neighborhood") != std::string::npos);
    std::snprintf(diff.semanticFilter_, sizeof(diff.semanticFilter_), "%s", "0x20");
    paintSemantic(); paintSemantic();
    CHECK(diff.semanticVisibleMatches_.size() == 1 && diff.semanticSelectedMatch_ == 2);
    CHECK(diff.semanticVisibleRemoved_.size() == 1);
    diff.semanticFilter_[0] = 0;
    diff.semanticChangesOnly_ = true;
    diff.semanticFilterDirty_ = true;
    paintSemantic(); paintSemantic();
    CHECK(diff.semanticVisibleMatches_.size() == 1 && diff.semanticSelectedMatch_ == 1);
    std::snprintf(diff.semanticFilter_, sizeof(diff.semanticFilter_), "%s", "absent_function");
    paintSemantic(); paintSemantic(true);
    CHECK(diff.semanticVisibleMatches_.empty() && diff.semanticSelectedMatch_ == -1);
    CHECK(logged.find("No matches meet these filters") != std::string::npos);
    CHECK(logged.find("Baseline instructions") == std::string::npos);
    diff.semanticFilter_[0] = 0;
    diff.semanticChangesOnly_ = false;
    diff.semanticFilterDirty_ = true;
    paintSemantic(); paintSemantic();

    auto chooseSemanticTab = [&](const char* name) {
        ImGui::ClearActiveID();
        ImGui::FocusWindow(ImGui::FindWindowByName("Feature UI integration"));
        ImGuiTabBar* bar = ImGui::GetCurrentContext()->TabBars.GetByKey(semanticBarId);
        CHECK(bar != nullptr);
        if (!bar) return;
        bool found = false;
        for (ImGuiTabItem& item : bar->Tabs) {
            if (std::strcmp(ImGui::TabBarGetTabName(bar, &item), name) != 0) continue;
            const ImVec2 point(bar->BarRect.Min.x + item.Offset + item.Width * 0.5f,
                               (bar->BarRect.Min.y + bar->BarRect.Max.y) * 0.5f);
            const ImGuiID target = item.ID;
            ImGui::GetIO().AddMousePosEvent(point.x, point.y);
            // Mouse movement and button changes arrive on distinct frames, as
            // they do in the native host; settle hover before the press.
            paintSemantic(); paintSemantic();
            ImGui::GetIO().AddMouseButtonEvent(0, true);
            paintSemantic();
            ImGui::GetIO().AddMouseButtonEvent(0, false);
            paintSemantic(); paintSemantic();
            bar = ImGui::GetCurrentContext()->TabBars.GetByKey(semanticBarId);
            CHECK(bar && bar->SelectedTabId == target);
            found = true;
            break;
        }
        CHECK(found);
        paintSemantic(true);
    };
    chooseSemanticTab("Added");
    CHECK(logged.find("NewRequest") != std::string::npos);
    CHECK(logged.find("Baseline instructions") == std::string::npos);
    chooseSemanticTab("Removed");
    CHECK(logged.find("OldRequest") != std::string::npos);
    CHECK(logged.find("Baseline instructions") == std::string::npos);
    chooseSemanticTab("Transfer metadata (0)");
    CHECK(logged.find("No metadata transfer proposals") != std::string::npos);
    CHECK(logged.find("Baseline instructions") == std::string::npos);
    chooseSemanticTab("Matched");
    size = ImVec2(560.0f * scale, 850.0f * scale);
    paintSemantic(); paintSemantic(); paintSemantic(true);
    CHECK(logged.find("Baseline instructions") != std::string::npos);
    auto* instructions = activeWindow("/SemanticInstructions_");
    CHECK(instructions && instructions->ScrollMax.x > 0);
    diff.invalidateComparison();
    CHECK(diff.semanticFilterDirty_ && !diff.computed_ && !diff.semanticComputed_);

    // Actual byte-pane rendering retains complete rows at narrow widths, stacks
    // the source containers, and places them side by side again when widened.
    CHECK(diff.left_.loadRaw(path, 0));
    CHECK(diff.right_.loadRaw(path, 0));
    diff.selectedLeftPath_ = diff.selectedRightPath_ = path;
    diff.computed_ = true;
    diff.semanticMode_ = false;
    auto paintBytes = [&] {
        featureFrame([&] { diff.render(ctx); }, size);
        CHECK(ImGui::GetCurrentContext()->ErrorCountCurrentFrame == 0);
    };
    paintBytes(); paintBytes(); paintBytes();
    auto* leftPane = activeWindow("/Lcont_");
    auto* rightPane = activeWindow("/Rcont_");
    CHECK(leftPane && rightPane);
    if (leftPane && rightPane) CHECK(rightPane->Pos.y >= leftPane->Pos.y + leftPane->Size.y);
    auto* leftHex = activeWindow("/Lhex_");
    auto* rightHex = activeWindow("/Rhex_");
    CHECK(leftHex && (leftHex->Flags & ImGuiWindowFlags_HorizontalScrollbar));
    CHECK(rightHex && (rightHex->Flags & ImGuiWindowFlags_HorizontalScrollbar));
    size = ImVec2(1400.0f * scale, 850.0f * scale);
    paintBytes(); paintBytes();
    leftPane = activeWindow("/Lcont_");
    rightPane = activeWindow("/Rcont_");
    CHECK(leftPane && rightPane);
    if (leftPane && rightPane) CHECK(rightPane->Pos.x >= leftPane->Pos.x + leftPane->Size.x);
    ImGui::ClearActiveID();
    ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
}
