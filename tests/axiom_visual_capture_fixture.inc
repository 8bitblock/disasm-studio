// Optional visual evidence for the production-object feature harness.
// Include after featureFrame/featureLoadRaw and the private-exposed tab headers.
// Call captureAxiomAnalysisPages(rawPath, outputDirectory) only after the normal
// assertions, with the production font atlas built at the current UI scale.
// Findings below are explicitly authored fixture data, not analysis claims.
#include "ui_capture.h"

static void captureAxiomAnalysisPages(const std::string& rawPath,
                                     const std::filesystem::path& outputDirectory) {
    const auto priorTheme = theme::CurrentTheme();
    theme::ApplyTheme(theme::ThemeId::Axiom);
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGui::GetIO().ClearInputKeys();
    ImGui::GetIO().ClearInputMouse();
    ImGui::GetIO().AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    const auto capture = [&](const char* name, const std::function<void()>& body,
                             ImVec2 size = ImVec2(1440, 900)) {
        for (int frame = 0; frame < 3; ++frame) featureFrame(body, size);
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
        std::string error;
        const auto path = outputDirectory / (std::string(name) + ".bmp");
        const bool saved = ds::test::captureUiFrame(path, &error);
        CHECK(saved);
        std::printf("UI capture %s: %s\n", name, saved ? path.string().c_str() : error.c_str());
    };
    AppContext ctx;
    featureLoadRaw(ctx, rawPath);
    const auto identity = MakeDocumentResultIdentity(ctx.staticDocumentId(), ctx.staticImageGeneration(),
        true, ctx.staticBinary().contentHash(), ctx.staticBinary().imageRevision());

    ProjectsTab projects;
    projects.loaded_ = projects.lastSeenBinaryLoaded_ = true;
    projects.lastSeenHash_ = ctx.staticProject().hash;
    for (int i = 0; i < 7; ++i) {
        RecentEntry recent;
        recent.hash = i == 0 ? ctx.staticProject().hash : static_cast<uint64_t>(100 + i);
        recent.name = i == 0 ? "Authored UI fixture" : "Fixture comparison " + std::to_string(i);
        recent.path = i == 0 ? rawPath : "C:\\Fixture images\\comparison-" + std::to_string(i) + ".bin";
        recent.arch = i % 2 ? "ARM64" : "x64";
        recent.status = "Authored visual fixture";
        recent.lastOpenedUnix = 1788825600 - i * 86400;
        projects.recents_.push_back(std::move(recent));
    }
    projects.selectedHash_ = ctx.staticProject().hash;
    projects.selectedHashValid_ = true;
    capture("projects-wide", [&] { projects.render(ctx); });
    capture("projects-compact", [&] { projects.render(ctx); }, ImVec2(720, 780));

    SigScannerTab scanner;
    scanner.libraryStarted_ = scanner.libraryReady_ = true;
    scanner.staticResultsOwner_ = scanner.healthOwner_ = scanner.functionsOwner_ = identity;
    scanner.functionsEngine_ = ctx.staticEngine();
    scanner.functionsArch_ = ctx.staticArch();
    scanner.scanCompleted_ = true;
    scanner.progress_ = 1.0f;
    scanner.scanPattern_ = "C3";
    scanner.scanTarget_ = "FILE / Authored UI fixture";
    std::snprintf(scanner.patternInput_, sizeof(scanner.patternInput_), "C3");
    std::snprintf(scanner.sigName_, sizeof(scanner.sigName_), "fixture_return");
    for (int i = 0; i < 24; ++i) {
        scanner.results_.push_back({static_cast<uint64_t>(i * 16), "C3", "Authored fixture", false});
        scanner.functions_.push_back({static_cast<uint64_t>(i * 16), "fixture_function_" + std::to_string(i), 16});
    }
    scanner.scanPartial_ = true;
    scanner.scanCoverageStatus_ = "Authored visual sample: 24 result rows; not a completed scan.";
    for (int i = 0; i < 5; ++i) {
        SigScannerTab::Sig signature;
        signature.id = static_cast<uint64_t>(i + 1);
        signature.name = "fixture_signature_" + std::to_string(i);
        signature.pattern = i % 2 ? "C3 ?? C3" : "C3";
        signature.architecture = "x64";
        signature.health = "Authored fixture";
        signature.count = 24;
        scanner.sigs_.push_back(std::move(signature));
    }
    const char* scanCaptures[] = {"scanner-results", "scanner-current", "scanner-health", "scanner-functions"};
    for (int tab = 0; tab < 4; ++tab) {
        scanner.requestedSub_ = tab;
        capture(scanCaptures[tab], [&] { scanner.render(ctx); });
    }
    scanner.requestedSub_ = 0;
    capture("scanner-compact", [&] { scanner.render(ctx); }, ImVec2(720, 780));

    BinaryTechTab tech;
    tech.owner_ = identity;
    tech.scanned_ = true;
    tech.selected_ = 0;
    for (int i = 0; i < 8; ++i) {
        Capability finding;
        finding.name = i == 0 ? "Network request fixture" : "Capability fixture " + std::to_string(i);
        finding.category = i % 2 ? "crypto" : "network";
        finding.detail = "Authored visual fixture for inspecting confidence, source evidence and FILE navigation. "
                         "These rows exercise the production rendering and do not assert capabilities of this raw file.";
        finding.analyzer = "Authored fixture";
        finding.confidence = 0.93f - static_cast<float>(i) * 0.06f;
        finding.address = static_cast<uint64_t>(i * 16);
        finding.addressValid = true;
        finding.addresses = {finding.address, finding.address + 8};
        finding.hitCount = 3;
        tech.caps_.push_back(std::move(finding));
    }
    capture("binary-tech-wide", [&] { tech.render(ctx); });
    capture("binary-tech-compact", [&] { tech.render(ctx); }, ImVec2(720, 780));

    BinaryDiffTab diff;
    CHECK(diff.left_.loadRaw(rawPath, 0));
    CHECK(diff.right_.loadRaw(rawPath, 0));
    const uint8_t candidateByte = 0x90;
    CHECK(diff.right_.writeImage(32, &candidateByte, 1) == 1);
    diff.selectedLeftPath_ = diff.selectedRightPath_ = rawPath;
    diff.leftIdentity_.size = diff.left_.bytes().size();
    diff.rightIdentity_.size = diff.right_.bytes().size();
    diff.computed_ = true;
    diff.semanticMode_ = false;
    diff.totalDiff_ = 1;
    diff.regions_.push_back({32, 33});
    diff.curRegion_ = 0;
    capture("binary-diff-bytes", [&] { diff.render(ctx); });
    capture("binary-diff-compact", [&] { diff.render(ctx); }, ImVec2(720, 780));
    diff.semanticMode_ = diff.semanticComputed_ = true;
    diff.semanticLeft_.emplace();
    diff.semanticRight_.emplace();
    diff.semanticDiff_.complete = true;
    for (int i = 0; i < 6; ++i) {
        SemanticFunction function;
        function.address = static_cast<uint64_t>(i * 16);
        function.name = "fixture_function_" + std::to_string(i);
        SemanticInstruction instruction;
        instruction.address = function.address;
        instruction.length = 1;
        instruction.mnemonic = instruction.display = "ret";
        function.instructions.push_back(instruction);
        diff.semanticLeft_->functions.push_back(function);
        diff.semanticRight_->functions.push_back(function);
        SemanticFunctionMatch match;
        match.leftIndex = match.rightIndex = static_cast<size_t>(i);
        match.leftAddress = match.rightAddress = function.address;
        match.confidence = 0.95f;
        match.evidence = "Authored visual fixture: matching instruction semantics";
        diff.semanticDiff_.matched.push_back(std::move(match));
    }
    diff.semanticSelectedMatch_ = 0;
    capture("binary-diff-semantic", [&] { diff.render(ctx); });

    // Prior production tests can leave analyst overrides in this isolated raw
    // file's sidecar. The authored report has no analyst knowledge, so give it
    // an explicitly empty knowledge scope instead of bypassing retirement.
    ctx.staticProject().names.clear();
    ctx.staticProject().algorithmLabels.clear();
    ctx.staticProject().functionOverrides.clear();
    ctx.staticProject().dataOverrides.clear();
    CortexTab cortex;
    cortex.observedIdentity_ = cortex.analyzedIdentity_ = MakeDocumentResultIdentity(
        ctx.staticDocumentId(), ctx.staticImageGeneration(), true,
        ctx.staticBinary().contentHash(), ctx.staticBinary().imageRevision());
    cortex.analyzedKnowledge_ = 0;
    cortex.analyzed_ = true;
    cortex.analyzedEngine_ = ctx.staticEngine();
    cortex.analyzedArch_ = ctx.staticArch();
    cortex.rep_.headline = "Authored Cortex visual fixture";
    cortex.rep_.verdict = "Production report rendering with synthetic findings for reviewing evidence hierarchy and navigation.";
    cortex.rep_.facts = {"Raw image", "x64", "FILE entry 0x0", "Fixture data"};
    cortex.behSel_ = 0;
    for (int i = 0; i < 6; ++i) {
        CortexBehavior behavior;
        behavior.title = i == 0 ? "Network request fixture" : "Static behavior fixture " + std::to_string(i);
        behavior.confidence = 0.90f - static_cast<float>(i) * 0.06f;
        behavior.explanation = "This authored finding exercises the selected-evidence inspector.";
        behavior.evidence = "Authored fixture; no runtime observation or capability claim.";
        behavior.specifics = {"Evidence and exact FILE locations remain distinct from confidence."};
        behavior.addresses = {static_cast<uint64_t>(i * 16), static_cast<uint64_t>(i * 16 + 8)};
        cortex.rep_.behaviors.push_back(std::move(behavior));
        CortexFuncBrief function;
        function.address = static_cast<uint64_t>(i * 16);
        function.name = "fixture_function_" + std::to_string(i);
        function.brief = "Static interpretation from authored fixture evidence.";
        function.basis = "Authored visual fixture";
        function.guessed = i != 0;
        cortex.rep_.functions.push_back(function);
        cortex.rep_.highlights.push_back(std::move(function));
    }
    cortex.chat_.push_back({"What evidence is available?",
        "This authored visual fixture shows the report's evidence, confidence and FILE navigation presentation."});
    const auto renderCortex = [&](const char* expectedPane) {
        ImGui::LogToBuffer();
        cortex.render(ctx);
        const std::string text = GImGui->LogBuffer.c_str();
        ImGui::LogFinish();
        CHECK(cortex.analyzed_ && cortex.rep_.behaviors.size() == 6 && cortex.behSel_ == 0);
        CHECK(text.find("Ready to analyze") == std::string::npos);
        CHECK(text.find(expectedPane) != std::string::npos);
    };
    capture("cortex-wide", [&] { renderCortex("Selected evidence"); });
    for (int pane = 0; pane < 3; ++pane) {
        cortex.compactPane_ = pane;
        const char* names[] = {"cortex-compact-behaviors", "cortex-compact-functions", "cortex-compact-questions"};
        const char* expected[] = {"Selected evidence", "Function briefs", "Answers from this static report"};
        capture(names[pane], [&] { renderCortex(expected[pane]); }, ImVec2(720, 780));
    }
    theme::ApplyTheme(priorTheme);
}
