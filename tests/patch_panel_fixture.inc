// Real mouse input through the production patch drawer. Keyboard activation
// alone would miss a full-row Selectable swallowing the Revert button.
#include "ui_capture.h"

static ImGuiTable* patchPanelTable() {
    for (int index = 0; index < GImGui->Tables.GetMapSize(); ++index) {
        ImGuiTable* table = GImGui->Tables.TryGetMapData(index);
        if (table && table->LastFrameActive == ImGui::GetFrameCount() &&
            table->InnerWindow && std::strstr(table->InnerWindow->Name, "/patches_"))
            return table;
    }
    return nullptr;
}

static void checkPatchPanelRestoration(const std::string& path) {
    const int failuresBefore = failures;
    const float priorScale = theme::UiScale();
    const auto priorTheme = theme::CurrentTheme();
    char captureDirectory[2048]{};
    GetEnvironmentVariableA("DS_PATCH_PANEL_CAPTURE_DIR", captureDirectory,
                            static_cast<DWORD>(sizeof(captureDirectory)));
    auto capture = [&](const std::string& filename) {
        if (!captureDirectory[0]) return;
        std::string error;
        const bool captured = ds::test::captureUiFrame(
            std::filesystem::path(captureDirectory) / (filename + ".bmp"), &error);
        CHECK(captured);
        if (!captured) std::printf("Patch panel capture: %s\n", error.c_str());
    };
    for (float scale : {0.9f, 1.5f}) {
        theme::SetUiScale(scale);
        theme::ApplyTheme(theme::ThemeId::Axiom);
        ui::LoadFonts(scale);
        unsigned char* pixels = nullptr;
        int width = 0, height = 0;
        ImGui::GetIO().Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
        CHECK(pixels && width > 0 && height > 0);
        for (bool fullWorkbench : {true, false}) {
            ImGui::ClosePopupsOverWindow(nullptr, false);
            ImGui::ClearActiveID();
            ImGuiIO& io = ImGui::GetIO();
            io.ClearInputKeys(); io.ClearInputMouse();
            Fixture f(path);
            f.tab->mainView_ = 7;
            f.tab->lowerDockCollapsed_ = false;
            f.tab->lowerAdvancedMode_ = false;
            f.tab->cursorValid_ = false;
            // A large inventory of sets must not take height from the records.
            for (uint64_t id = 1; id <= 30; ++id)
                f.ctx.staticProject().patchSets.push_back({id, "Experiment " + std::to_string(id), false});
            size_t available = 0;
            const uint8_t* original = f.ctx.staticBinary().ptrFromVA(kTarget, available);
            CHECK(original && available >= 8);
            if (!original || available < 8) continue;
            const std::vector<uint8_t> pristine(original, original + 8);
            CHECK(f.tab->applyPatchBytes(f.ctx, kTarget, {0x90, 0x90}, 2, false));
            CHECK(f.tab->applyPatchBytes(f.ctx, kTarget + 4, {0xCC, 0xCC}, 2, false));
            CHECK(f.ctx.staticProject().patches.size() == 2);
            const char* title = fullWorkbench ? "Patch workbench QA" : "Compact patch drawer QA";
            const ImVec2 size = fullWorkbench ? ImVec2(1366, 800) : ImVec2(420, 260);
            auto paint = [&] {
                frame([&] {
                    f.tab->frameSnap_ = &f.detached;
                    if (fullWorkbench) f.tab->render(f.ctx);
                    else f.tab->renderLowerTabs(f.ctx, false);
                }, title, size);
                f.tab->frameSnap_ = &f.detached;
                CHECK(GImGui->ErrorCountCurrentFrame == 0);
            };
            auto settle = [&] { paint(); paint(); paint(); };
            settle();
            ImGuiWindow* owner = fullWorkbench ? releaseWindow("##bottom_tool_drawer")
                                              : ImGui::FindWindowByName(title);
            CHECK(owner != nullptr);
            if (!owner) continue;
            const ImGuiID barId = owner->GetID("lower_primary");
            ImGuiTabBar* bar = GImGui->TabBars.GetByKey(barId);
            CHECK(bar != nullptr);
            if (!bar) continue;
            const ImGuiID patchTabId = ImHashStr("Patches###lower_patches", 0, barId);
            ImGuiTabItem* tab = ImGui::TabBarFindTabByID(bar, patchTabId);
            CHECK(tab != nullptr);
            if (!tab) continue;
            ImGui::TabBarQueueFocus(bar, tab);
            settle();
            // Patches is a fixed trailing tab: it must keep its complete label
            // even when the scrolling tabs and utility buttons compete for
            // room at 420 pixels with the actual 150% font atlas.
            bar = GImGui->TabBars.GetByKey(barId);
            tab = bar ? ImGui::TabBarFindTabByID(bar, patchTabId) : nullptr;
            CHECK(bar && tab);
            if (bar && tab) {
                CHECK((tab->Flags & ImGuiTabItemFlags_Trailing) != 0);
                CHECK(bar->SelectedTabId == patchTabId && bar->VisibleTabId == patchTabId);
                const ImRect bounds(
                    ImVec2(bar->BarRect.Min.x + tab->Offset, bar->BarRect.Min.y),
                    ImVec2(bar->BarRect.Min.x + tab->Offset + tab->Width, bar->BarRect.Max.y));
                CHECK(bounds.GetWidth() >= ImGui::CalcTextSize("Patches").x + 8.0f);
                CHECK(bounds.Min.x >= bar->BarRect.Min.x - 1.0f);
                CHECK(bounds.Max.x <= bar->BarRect.Max.x + 1.0f);
                CHECK(bounds.Min.x >= owner->InnerClipRect.Min.x - 1.0f);
                CHECK(bounds.Max.x <= owner->InnerClipRect.Max.x + 1.0f);
            }
            ImGuiTable* table = patchPanelTable();
            CHECK(table && table->InnerWindow);
            if (!table || !table->InnerWindow) continue;
            CHECK(table->InnerWindow->InnerClipRect.GetHeight() >= 2.0f * ImGui::GetTextLineHeight());
            CHECK(table->FreezeColumnsRequest == 1 && table->FreezeRowsRequest == 1);
            CHECK(table->Columns[0].WorkMinX >= owner->InnerClipRect.Min.x - 1.0f);
            CHECK(table->Columns[0].MaxX <= owner->InnerClipRect.Max.x + 1.0f);
            const std::string suffix = std::string(fullWorkbench ? "workbench-" : "compact-") +
                (scale < 1.0f ? "90" : "150");
            capture("patch-records-" + suffix);

            auto clickLastRevert = [&] {
                ImGuiTable* current = patchPanelTable();
                CHECK(current && current->InnerWindow);
                if (!current || !current->InnerWindow) return;
                const ImVec2 point(current->Columns[0].WorkMinX + 12.0f * scale,
                    current->RowPosY1 + ImGui::GetStyle().CellPadding.y + ImGui::GetTextLineHeight() * 0.5f);
                CHECK(current->InnerWindow->InnerClipRect.Contains(point));
                io.AddMousePosEvent(point.x, point.y); paint(); paint();
                io.AddMouseButtonEvent(ImGuiMouseButton_Left, true); paint();
                io.AddMouseButtonEvent(ImGuiMouseButton_Left, false); settle();
                io.AddMousePosEvent(-100, -100);
            };
            // Scroll the byte columns away first. The frozen Revert action must
            // remain clickable, and it must remove the clicked second record.
            ImGui::SetScrollX(table->InnerWindow, table->InnerWindow->ScrollMax.x);
            settle();
            clickLastRevert();
            CHECK(f.ctx.staticProject().patches.size() == 1);
            if (f.ctx.staticProject().patches.size() == 1)
                CHECK(f.ctx.staticProject().patches.front().address == kTarget);
            original = f.ctx.staticBinary().ptrFromVA(kTarget, available);
            CHECK(original && available >= 8 && original[0] == 0x90 &&
                original[1] == 0x90 && original[4] == pristine[4] && original[5] == pristine[5]);
            CHECK(!f.tab->patchStatus_.empty());
            clickLastRevert();
            CHECK(f.ctx.staticProject().patches.empty());
            original = f.ctx.staticBinary().ptrFromVA(kTarget, available);
            CHECK(original && available >= 8 && std::equal(pristine.begin(), pristine.end(), original));
            capture("patch-restored-" + suffix);

            // Set authoring remains reachable in a bounded scrolling modal.
            ImGui::FocusWindow(owner);
            ImGui::ActivateItemByID(ImHashStr("Sets & compare...", 0, patchTabId));
            settle();
            ImGuiWindow* manager = releaseWindow("Patch sets & comparison");
            CHECK(manager != nullptr);
            if (manager) {
                CHECK(manager->Size.x <= size.x && manager->Size.y <= size.y);
                ImGuiTable* sets = GImGui->Tables.GetByKey(manager->GetID("##patchsets"));
                CHECK(sets && sets->InnerWindow && sets->InnerWindow->ScrollMax.y > 0.0f);
                capture("patch-manager-" + suffix);
            }
            ImGui::ClosePopupsOverWindow(nullptr, false);
            ImGui::ClearActiveID();
            io.ClearInputKeys(); io.ClearInputMouse();
        }
    }
    theme::SetUiScale(priorScale);
    theme::ApplyTheme(priorTheme);
    ui::LoadFonts(priorScale);
    unsigned char* pixels = nullptr;
    int width = 0, height = 0;
    ImGui::GetIO().Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    CHECK(pixels && width > 0 && height > 0);
    std::printf("Patch drawer mouse restoration and fit: %s (%d new failure(s))\n",
        failures == failuresBefore ? "passed" : "FAILED", failures - failuresBefore);
}
