// Actual BinaryViewTab navigation/preset contracts, using the existing isolated
// production-object ImGui fixture. No target is launched or attached.
static void checkIntentWorkflows(const std::string& path) {
    Fixture f(path);
    frame([&] {
        f.tab->applyWorkflow(f.ctx, 0);
        CHECK(f.tab->mainView_ == 0 && f.tab->lowerAdvancedMode_);
        CHECK(f.ctx.requestedCrackmeTriage && !f.tab->lowerDockCollapsed_);
        f.ctx.requestedCrackmeTriage = false;
        f.tab->applyWorkflow(f.ctx, 1);
        CHECK(f.ctx.requestedTab == "Communications");
        CHECK(f.tab->focusRegistersTab_ && !f.tab->lowerAdvancedMode_);
        CHECK(!f.ctx.debug.lifecycleSnapshot().busy);
        f.tab->applyWorkflow(f.ctx, 2);
        CHECK(f.tab->mainView_ == 2 && f.tab->focusTypesTab_);
        f.tab->applyWorkflow(f.ctx, 3);
        CHECK(f.ctx.requestedTab == "Binary Diff");

        f.tab->navigateToStaticView(0, DocumentView::Assembly);
        f.tab->viewPins_[0] = f.ctx.staticNavigation().current();
        CHECK(f.tab->viewPins_[0].valid && f.tab->viewPins_[0].va == 0);
        f.tab->selectRepresentation(f.ctx, 2);
        f.tab->setStaticCursor(kTarget + 8);
        f.tab->selectRepresentation(f.ctx, 0);
        CHECK(f.tab->cursorValid_ && f.tab->cursorVA_ == 0 && f.tab->mainView_ == 0);
        f.tab->viewPins_[0] = {};
        f.tab->selectRepresentation(f.ctx, 2);
        f.tab->setStaticCursor(kTarget + 16);
        f.tab->selectRepresentation(f.ctx, 0);
        CHECK(f.tab->cursorVA_ == kTarget + 16);
        f.tab->navigateTo(0);
        f.tab->navigateTo(kTarget);
        f.tab->navBack();
        const size_t backSize = f.ctx.staticNavigation().backStack().size();
        const size_t forwardSize = f.ctx.staticNavigation().forwardStack().size();
        CHECK(forwardSize > 0);
        f.tab->viewPins_[2] = {kTarget + 4, true, DocumentView::Hex, DocumentAddressSpace::File};
        f.tab->selectRepresentation(f.ctx, 2);
        CHECK(f.tab->cursorVA_ == kTarget + 4);
        CHECK(f.ctx.staticNavigation().backStack().size() == backSize);
        CHECK(f.ctx.staticNavigation().forwardStack().size() == forwardSize);
        f.tab->viewPins_[2] = {};
        f.tab->navigateToStaticView(0, DocumentView::Assembly);
        f.tab->viewPins_[0] = f.ctx.staticNavigation().current();
        f.tab->setStaticCursor(kTarget + 2);
        f.tab->navigateToStaticView(kTarget + 6, DocumentView::Hex);
        f.tab->selectRepresentation(f.ctx, 0);
        CHECK(f.tab->cursorVA_ == kTarget + 2);

        f.detached.state = DbgState::Paused; f.detached.pid = 42; f.detached.sessionGeneration = 2;
        f.detached.regs.rip = 0x9000;
        f.tab->viewPins_[4] = {0x8000, true, DocumentView::LiveAssembly,
            DocumentAddressSpace::Live, {42, 1}};
        f.tab->selectRepresentation(f.ctx, 4);
        CHECK(!f.tab->viewPins_[4].valid);
        CHECK(!f.tab->cursorValid_ || f.tab->cursorVA_ != 0x8000);
        f.detached = {};
        f.tab->selectRepresentation(f.ctx, 0);
    });

    // Shared authored type names update both inspector/hex presentation without
    // copying labels into independent view caches.
    TypeDefinition scalar; scalar.id = 1; scalar.name = "uint32_t";
    TypeDefinition structure; structure.id = 2; structure.name = "Player";
    structure.kind = TypeKind::Structure; structure.fields = {{1, "health", 1, 0}};
    f.ctx.staticProject().typeRegistry.types = {scalar, structure};
    f.ctx.staticProject().typeRegistry.applications = {{0, 2, "player"}};
    CHECK(ValidateTypeRegistry(f.ctx.staticProject().typeRegistry));
    f.tab->lowerAdvancedMode_ = true; f.tab->focusTypesTab_ = true;
    // ImGui queues selection while discovering a new tab. The following frame
    // makes it visible and consumes the request, just as the native render loop.
    for (int tabFrame = 0; tabFrame < 2; ++tabFrame) frame([&] {
        f.tab->renderTypedLocation(f.ctx, 0);
        f.tab->renderLowerTabs(f.ctx, false);
    });
    CHECK(!f.tab->focusTypesTab_);
    f.ctx.staticProject().typeRegistry.types[1].fields[0].name = "hitpoints";
    CHECK(ResolveTypeFieldAt(f.ctx.staticProject().typeRegistry, 2, 0, 4)->name == "hitpoints");

    // A valid persisted 64-bit identity may exhaust the monotone allocator.
    // Activate the real button: failure must remain visible without creating a
    // zero-ID dirty draft that hides its own Save/Discard controls.
    TypeDefinition lastIdentity;
    lastIdentity.id = UINT64_MAX; lastIdentity.name = "last_identity";
    f.ctx.staticProject().typeRegistry.types.push_back(lastIdentity);
    CHECK(ValidateTypeRegistry(f.ctx.staticProject().typeRegistry));
    CHECK(NextTypeId(f.ctx.staticProject().typeRegistry) == 0);
    std::string typeText;
    auto renderTypes = [&] {
        ImGui::LogToBuffer();
        f.tab->renderLowerTabs(f.ctx, false);
        typeText = ImGui::GetCurrentContext()->LogBuffer.c_str();
        ImGui::LogFinish();
    };
    frame(renderTypes);
    ImGuiWindow* typeWindow = nullptr;
    ImGuiWindow* parent = ImGui::FindWindowByName("Listing integration");
    if (parent) for (ImGuiWindow* child : parent->DC.ChildWindows)
        if (child->Active && std::string(child->Name).find("##type_workbench") != std::string::npos)
            typeWindow = child;
    CHECK(typeWindow != nullptr);
    const TypeId retainedDraftId = f.tab->typeDraft_.id;
    if (typeWindow) {
        ImGui::FocusWindow(typeWindow);
        ImGui::ActivateItemByID(typeWindow->GetID("New type"));
    }
    frame(renderTypes);
    CHECK(!f.tab->typeDraftDirty_ && f.tab->typeDraft_.id == retainedDraftId);
    CHECK(f.tab->typeStatus_.find("No more type identities") != std::string::npos);
    CHECK(typeText.find("No more type identities") != std::string::npos);
    CHECK(f.ctx.staticProject().typeRegistry.types.size() == 3);
    CHECK(ValidateTypeRegistry(f.ctx.staticProject().typeRegistry));

    for (const auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        theme::ApplyTheme(palette);
        frame([&] { f.tab->renderWorkflowContext(f.ctx); }, "Workflow controls", ImVec2(820, 560));
    }
    theme::ApplyTheme(theme::ThemeId::Midnight);
}

// Exercise the actual command band with long context, scaled controls, and
// keyboard copy. Source provenance must stay visible when context is elided.
static void checkWorkflowRefinement(const std::string& path) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGuiIO& io = ImGui::GetIO();
    ImGui::FocusWindow(nullptr);
    io.ClearInputKeys();
    io.ClearInputMouse();
    Fixture f(path);
    f.tab->functions_ = {{0, std::string(250, 'W') + "##literal_symbol", 32}};
    ++f.tab->functionsGen_;
    f.tab->funcIndexDirty_ = true;
    frame([&] { f.tab->navigateToStaticView(0, DocumentView::Assembly); });
    const float previousScale = theme::UiScale();
    const float previousFontScale = io.FontGlobalScale;
    ImVec2 breadcrumbMin, breadcrumbMax;
    ImVec2 size(540, 560);
    auto paint = [&] {
        frame([&] {
            f.tab->renderWorkflowContext(f.ctx);
            breadcrumbMin = ImGui::GetItemRectMin();
            breadcrumbMax = ImGui::GetItemRectMax();
        }, "Workflow refinement", size);
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    for (auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
        for (float scale : {1.0f, 1.5f, 2.0f}) {
            theme::SetUiScale(scale);
            io.FontGlobalScale = scale;
            theme::ApplyTheme(palette);
            for (float width : {340.0f, 540.0f, 820.0f}) {
                size = ImVec2(width * scale, 560.0f * scale);
                paint(); paint(); paint();
                ImGuiWindow* window = ImGui::FindWindowByName("Workflow refinement");
                CHECK(window && window->ScrollMax.x == 0.0f);
                CHECK(breadcrumbMin.x >= 0 && breadcrumbMax.x <= size.x);
                CHECK(breadcrumbMax.y <= size.y);
                // Source begins at the left and the complete address remains
                // at the right, despite a context much wider than the window.
                float first = FLT_MAX, last = -FLT_MAX;
                const ImU32 color = ImGui::GetColorU32(theme::col::accent());
                if (window) for (const auto& vertex : window->DrawList->VtxBuffer) {
                    if (vertex.col != color || vertex.pos.y < breadcrumbMin.y ||
                        vertex.pos.y > breadcrumbMax.y) continue;
                    first = std::min(first, vertex.pos.x);
                    last = std::max(last, vertex.pos.x);
                }
                CHECK(first < breadcrumbMin.x + 12.0f * scale);
                CHECK(last > breadcrumbMax.x - 20.0f * scale);
                CHECK(last <= breadcrumbMax.x);
            }
        }
    }
    theme::SetUiScale(previousScale);
    io.FontGlobalScale = previousFontScale;
    theme::ApplyTheme(theme::ThemeId::Midnight);
    size = ImVec2(540, 560);
    paint(); paint();
    ImGuiWindow* window = ImGui::FindWindowByName("Workflow refinement");
    CHECK(window != nullptr);
    if (window) {
        const ImGuiID id = window->GetID("##location_breadcrumb");
        ImGui::SetClipboardText("unchanged");
        ImGui::FocusWindow(window);
        // Use actual Tab input so ImGui establishes keyboard navigation and its
        // visible focus cursor, rather than only changing the internal NavId.
        for (int step = 0; step < 20; ++step) {
            io.AddKeyEvent(ImGuiKey_Tab, true);
            paint();
            io.AddKeyEvent(ImGuiKey_Tab, false);
            paint(); paint();
            if (GImGui->NavId == id) break;
        }
        CHECK(GImGui->NavId == id);
        io.AddKeyEvent(ImGuiKey_Space, true);
        paint();
        io.AddKeyEvent(ImGuiKey_Space, false);
        paint();
        CHECK(std::string(ImGui::GetClipboardText()) == "FILE:0x0");

        // Copy retains exact FILE-offset provenance and 64-bit address digits.
        f.tab->navigation_->replaceCurrent({UINT64_MAX, true, DocumentView::Hex,
                                            DocumentAddressSpace::FileOffset});
        paint();
        ImGui::ActivateItemByID(id);
        paint();
        CHECK(std::string(ImGui::GetClipboardText()) == "FILEOFF:0xFFFFFFFFFFFFFFFF");
        size = ImVec2(210, 560);
        ImGui::FocusWindow(nullptr);
        paint(); paint();
        CHECK(breadcrumbMax.y - breadcrumbMin.y >= ImGui::GetFontSize() * 2.0f);
        CHECK(window->ScrollMax.x == 0.0f);
        f.tab->navigation_->replaceCurrent({0xFEDCBA9876543210ull, true,
            DocumentView::LiveAssembly, DocumentAddressSpace::Live, {42, 1}});
        paint();
        ImGui::FocusWindow(window);
        ImGui::ActivateItemByID(id);
        paint();
        CHECK(std::string(ImGui::GetClipboardText()) == "LIVE:0xFEDCBA9876543210");
        f.tab->navigation_->replaceCurrent({});
        f.tab->cursorValid_ = false;
        ImGui::SetClipboardText("no location");
        ImGui::ActivateItemByID(id);
        paint();
        CHECK(std::string(ImGui::GetClipboardText()) == "no location");
    }
    io.ClearInputKeys();
    ImGui::ClearActiveID();
}
