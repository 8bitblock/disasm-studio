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
