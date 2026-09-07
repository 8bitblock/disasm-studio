// Exercise the production filter caches and explicit FILE handoffs.
static void checkFunctionNavigator(const std::string& path) {
    Fixture f(path);
    f.tab->functions_ = {{0, "Entry", 8}, {16, "ReadFile", 8}, {32, "ReadThunk", 8}};
    ++f.tab->functionsGen_;
    f.tab->funcIndexDirty_ = true;
    for (bool lower : {false, true}) {
        char* query = lower ? f.tab->funcTabFilter_ : f.tab->fnFilter_;
        auto& visible = lower ? f.tab->funcTabVisible_ : f.tab->fnVisible_;
        std::snprintf(query, 128, "%s", "READ -thunk");
        f.tab->refreshFunctionFilter(lower);
        CHECK(visible == std::vector<int>{1});
        const int* retained = visible.data();
        f.tab->refreshFunctionFilter(lower);
        CHECK(visible.data() == retained && visible == std::vector<int>{1});

        // Interior replacement leaves count/endpoints unchanged; the old
        // approximate cache signature missed this analysis update.
        f.tab->functions_[1].name = "WriteFile";
        ++f.tab->functionsGen_;
        f.tab->refreshFunctionFilter(lower);
        CHECK(visible.empty());
        f.tab->names_[16] = "Read Settings";
        ++f.tab->namesGen_;
        std::snprintf(query, 128, "%s", "\"READ SETTINGS\" 0x10");
        f.tab->refreshFunctionFilter(lower);
        CHECK(visible == std::vector<int>{1});
        std::snprintf(query, 128, "%s", "write 10");
        f.tab->refreshFunctionFilter(lower);
        CHECK(visible == std::vector<int>{1}); // original names stay searchable
        std::snprintf(query, 128, "%s", "0x0");
        f.tab->refreshFunctionFilter(lower);
        CHECK(visible == std::vector<int>{0});
        query[0] = 0;
        f.tab->refreshFunctionFilter(lower);
        CHECK(visible.size() == 3);
        f.tab->functions_[1].name = "ReadFile";
        f.tab->names_.clear();
        ++f.tab->functionsGen_; ++f.tab->namesGen_;
    }

    auto activateDestination = [&](const char* label) {
        auto render = [&] { f.tab->renderFunctionDestinations(f.ctx, 0); };
        frame(render, "Function destinations");
        ImGuiWindow* window = ImGui::FindWindowByName("Function destinations");
        CHECK(window != nullptr);
        if (window) {
            ImGui::FocusWindow(window);
            ImGui::ActivateItemByID(window->GetID(label));
        }
        frame(render, "Function destinations");
    };
    frame([&] { f.tab->navigateToStaticView(32, DocumentView::Hex); });
    activateDestination("Open in Pseudocode");
    CHECK(f.tab->mainView_ == 1 && f.tab->cursorValid_ && f.tab->cursorVA_ == 0);
    frame([&] { f.tab->navBack(); });
    CHECK(f.tab->mainView_ == 2 && f.tab->cursorVA_ == 32);
    activateDestination("Open in Control-flow graph");
    CHECK(f.tab->mainView_ == 3 && f.tab->cursorVA_ == 0);
    activateDestination("Open in Assembly");
    CHECK(f.tab->mainView_ == 0 && f.tab->cursorVA_ == 0 && !f.tab->cursorLive_);
    activateDestination("References to function");
    CHECK(f.tab->xrefTargetValid_ && f.tab->xrefPinned_ &&
          f.tab->xrefTarget_ == 0 && !f.tab->xrefHitsLive_);
}
