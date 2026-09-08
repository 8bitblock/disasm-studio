// Independent integration review: every shipped palette and density must keep
// the same destinations, shell bounds, and usable palette at both zoom sizes.
static void checkUiConsistencyMatrix() {
    ImGuiIO& io = ImGui::GetIO();
    const auto priorTheme = theme::CurrentTheme();
    const auto priorDensity = theme::CurrentDensity();
    const float priorScale = theme::UiScale();
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    io.ClearInputKeys(); io.ClearInputMouse();
    App app;
    const char* destinations[] = {"Projects", "Communications", "Sig Scanner", "Binary View",
        "Memory Tools", "Binary Diff", "Binary Tech", "Cortex", "Prism"};
    for (float scale : {0.9f, 1.5f}) {
        ui::LoadFonts(scale);
        unsigned char* pixels = nullptr; int width = 0, height = 0;
        io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
        CHECK(pixels && width > 0 && height > 0);
        theme::SetUiScale(scale);
        for (auto density : {theme::Density::Compact, theme::Density::Comfortable, theme::Density::Spacious}) {
            theme::SetDensity(density);
            for (int palette = 0; palette < static_cast<int>(theme::ThemeId::Count); ++palette) {
                const auto selectedTheme = static_cast<theme::ThemeId>(palette);
                theme::ApplyTheme(selectedTheme);
                for (const ImVec2 size : {ImVec2(820, 560), ImVec2(1600, 960)}) {
                    std::printf("[consistency] %s / %s / %.1fx / %.0fx%.0f\n",
                        theme::ThemeName(selectedTheme), theme::DensityName(density), scale, size.x, size.y);
                    for (int settle = 0; settle < 3; ++settle) workbenchFrame(app, size);
                    for (int tab = 0; tab < 9; ++tab) {
                        workbenchChord(app, size, static_cast<ImGuiKey>(ImGuiKey_1 + tab));
                        checkWorkbenchDestination(destinations[tab]);
                        checkWorkbenchBounds(size);
                        CHECK(GImGui->ErrorCountCurrentFrame == 0);
                    }
                    workbenchChord(app, size, ImGuiKey_K);
                    for (int settle = 0; settle < 3; ++settle) workbenchFrame(app, size);
                    ImGuiWindow* paletteWindow = ImGui::FindWindowByName("##cmdpalette");
                    CHECK(paletteWindow && paletteWindow->LastFrameActive == ImGui::GetFrameCount());
                    if (paletteWindow) {
                        CHECK(paletteWindow->Pos.x >= 0 && paletteWindow->Pos.y >= 0);
                        CHECK(paletteWindow->Pos.x + paletteWindow->Size.x <= size.x + 1);
                        CHECK(paletteWindow->Pos.y + paletteWindow->Size.y <= size.y + 1);
                        CHECK(paletteWindow->ScrollMax.x <= 1 && paletteWindow->ScrollMax.y <= 1);
                    }
                    CHECK(GImGui->ErrorCountCurrentFrame == 0);
                    workbenchChord(app, size, ImGuiKey_K);
                    CHECK(!app.wantsExit());
                }
            }
        }
    }
    theme::SetUiScale(priorScale); theme::SetDensity(priorDensity); theme::ApplyTheme(priorTheme);
    ui::LoadFonts(priorScale);
    unsigned char* pixels = nullptr; int width = 0, height = 0;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    io.ClearInputKeys(); io.ClearInputMouse();
}
