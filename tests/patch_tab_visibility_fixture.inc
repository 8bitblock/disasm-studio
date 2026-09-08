// The recovery destination stays on both drawer rails, including an empty
// project and a collapsed drawer. Exercise actual mouse input and tab bounds.
static void checkPatchTabVisibility(const std::string& path) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGuiIO& io = ImGui::GetIO();
    io.ClearInputKeys(); io.ClearInputMouse();
    Fixture f(path);
    const char* title = "Permanent Patches tab QA";
    for (float width : {420.0f, 760.0f, 1200.0f}) {
        for (bool advanced : {false, true}) {
            f.tab->lowerAdvancedMode_ = advanced;
            f.tab->lowerDockCollapsed_ = true;
            auto paint = [&] {
                frame([&] {
                    f.tab->frameSnap_ = &f.detached;
                    f.tab->renderLowerTabs(f.ctx, f.tab->lowerDockCollapsed_);
                }, title, ImVec2(width, 220));
                CHECK(GImGui->ErrorCountCurrentFrame == 0);
            };
            auto settle = [&] { paint(); paint(); paint(); };
            settle();
            ImGuiWindow* window = ImGui::FindWindowByName(title);
            CHECK(window != nullptr);
            if (!window) continue;
            const ImGuiID barId = window->GetID(advanced ? "lower_secondary" : "lower_primary");
            const ImGuiID tabId = ImHashStr("Patches###lower_patches", 0, barId);
            auto patchBounds = [&]() -> ImRect {
                ImGuiTabBar* bar = GImGui->TabBars.GetByKey(barId);
                CHECK(bar != nullptr);
                if (!bar) return {};
                ImGuiTabItem* item = ImGui::TabBarFindTabByID(bar, tabId);
                CHECK(item != nullptr);
                if (!item) return {};
                CHECK(item->LastFrameVisible == ImGui::GetFrameCount());
                CHECK((item->Flags & ImGuiTabItemFlags_Trailing) != 0);
                const ImRect bounds(ImVec2(bar->BarRect.Min.x + item->Offset, bar->BarRect.Min.y),
                    ImVec2(bar->BarRect.Min.x + item->Offset + item->Width, bar->BarRect.Max.y));
                CHECK(bounds.Min.x >= bar->BarRect.Min.x - 1.0f);
                CHECK(bounds.Max.x <= bar->BarRect.Max.x + 1.0f);
                CHECK(bounds.GetWidth() >= ImGui::CalcTextSize("Patches").x + 8.0f);
                return bounds;
            };
            const ImRect bounds = patchBounds();
            if (bounds.GetWidth() <= 0) continue;
            io.AddMousePosEvent(bounds.GetCenter().x, bounds.GetCenter().y);
            paint();
            io.AddMouseButtonEvent(ImGuiMouseButton_Left, true); paint();
            io.AddMouseButtonEvent(ImGuiMouseButton_Left, false); settle();
            CHECK(!f.tab->lowerDockCollapsed_);
            ImGuiTabBar* bar = GImGui->TabBars.GetByKey(barId);
            CHECK(bar && bar->SelectedTabId == tabId && bar->VisibleTabId == tabId);
            patchBounds();
            // Scrolling the ordinary tabs cannot carry the fixed Patches tab away.
            if (bar) bar->ScrollingTarget = bar->ScrollingAnim = 10000.0f;
            settle();
            patchBounds();
            CHECK(f.ctx.staticProject().patches.empty());
            io.AddMousePosEvent(-100, -100);
        }
    }
}
